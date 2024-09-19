package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/coreos/go-iptables/iptables"
	"github.com/gin-contrib/timeout"
	"github.com/gin-gonic/gin"
	"github.com/gorilla/websocket"
	"github.com/shirou/gopsutil/process"
	"github.com/spf13/viper"
	"github.com/uber-go/zap"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/time/rate"
)

var (
	ipt      *iptables.IPTables
	upgrader = websocket.Upgrader{
		CheckOrigin: func(r *http.Request) bool {
			return true
		},
	}
	logger *zap.Logger
	limiter = rate.NewLimiter(rate.Every(time.Second), 10) // 10 requests per second
)

func init() {
	var err error
	
	// Initialize logger
	logger, err = zap.NewProduction()
	if err != nil {
		panic(fmt.Sprintf("Failed to initialize logger: %v", err))
	}
	defer logger.Sync()

	// Load configuration
	viper.SetConfigName("config")
	viper.AddConfigPath(".")
	if err := viper.ReadInConfig(); err != nil {
		logger.Fatal("Failed to read config file", zap.Error(err))
	}

	// Initialize iptables
	ipt, err = iptables.New()
	if err != nil {
		logger.Fatal("Failed to initialize iptables", zap.Error(err))
	}
}

func requireAPIKey() gin.HandlerFunc {
	return func(c *gin.Context) {
		apiKey := c.GetHeader("X-API-Key")
		if apiKey != viper.GetString("api_key") {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid API key"})
			c.Abort()
			return
		}
		c.Next()
	}
}

func rateLimitMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		if !limiter.Allow() {
			c.JSON(http.StatusTooManyRequests, gin.H{"error": "Rate limit exceeded"})
			c.Abort()
			return
		}
		c.Next()
	}
}

func validateRuleData(ruleData map[string]interface{}, requiredFields []string) map[string]string {
	errors := make(map[string]string)
	for _, field := range requiredFields {
		if _, ok := ruleData[field]; !ok {
			errors[field] = fmt.Sprintf("Missing required field: %s", field)
		} else if field == "port" {
			if _, ok := ruleData[field].(float64); !ok {
				errors[field] = "Port must be a number"
			}
		} else if field == "protocol" {
			protocol, ok := ruleData[field].(string)
			if !ok || (protocol != "tcp" && protocol != "udp") {
				errors[field] = "Protocol must be 'tcp' or 'udp'"
			}
		}
	}
	return errors
}

func applyRules(c *gin.Context) {
	var request struct {
		Rules []map[string]interface{} `json:"rules"`
	}
	if err := c.ShouldBindJSON(&request); err != nil {
		logger.Error("Failed to bind JSON", zap.Error(err))
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	results := make([]map[string]interface{}, 0)
	for _, rule := range request.Rules {
		errors := validateRuleData(rule, []string{"protocol", "port", "action"})
		if len(errors) > 0 {
			results = append(results, map[string]interface{}{
				"rule":    rule,
				"success": false,
				"errors":  errors,
			})
		} else {
			chain := "INPUT"
			if chainVal, ok := rule["chain"]; ok {
				chain = chainVal.(string)
			}
			port := int(rule["port"].(float64))
			err := ipt.Append("filter", chain, "-p", rule["protocol"].(string), "--dport", strconv.Itoa(port), "-j", rule["action"].(string))
			if err != nil {
				logger.Error("Failed to append iptables rule", zap.Error(err), zap.Any("rule", rule))
				results = append(results, map[string]interface{}{
					"rule":    rule,
					"success": false,
					"error":   err.Error(),
				})
			} else {
				logger.Info("Applied iptables rule", zap.Any("rule", rule))
				results = append(results, map[string]interface{}{
					"rule":    rule,
					"success": true,
				})
			}
		}
	}

	c.JSON(http.StatusOK, gin.H{"status": "completed", "results": results})
}

func getIPTablesRules(c *gin.Context) {
	rules, err := ipt.List("filter", "INPUT")
	if err != nil {
		logger.Error("Failed to list iptables rules", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	logger.Info("Retrieved iptables rules", zap.Int("count", len(rules)))
	c.JSON(http.StatusOK, gin.H{"status": "success", "rules": rules})
}

func deleteRule(c *gin.Context) {
	var request struct {
		Chain    string                 `json:"chain"`
		RuleSpec map[string]interface{} `json:"rule_spec"`
		Table    string                 `json:"table"`
	}
	if err := c.ShouldBindJSON(&request); err != nil {
		logger.Error("Failed to bind JSON", zap.Error(err))
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	ruleArgs := []string{"-p", request.RuleSpec["protocol"].(string)}
	if port, ok := request.RuleSpec["port"]; ok {
		ruleArgs = append(ruleArgs, "--dport", strconv.Itoa(int(port.(float64))))
	}
	if target, ok := request.RuleSpec["target"]; ok {
		ruleArgs = append(ruleArgs, "-j", target.(string))
	}

	err := ipt.Delete(request.Table, request.Chain, ruleArgs...)
	if err != nil {
		logger.Error("Failed to delete iptables rule", zap.Error(err), zap.Any("request", request))
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	logger.Info("Deleted iptables rule", zap.Any("request", request))
	c.JSON(http.StatusOK, gin.H{"status": "success", "message": "Rule deleted successfully"})
}

func flushChain(c *gin.Context) {
	var request struct {
		Chain string `json:"chain"`
		Table string `json:"table"`
	}
	if err := c.ShouldBindJSON(&request); err != nil {
		logger.Error("Failed to bind JSON", zap.Error(err))
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	err := ipt.ClearChain(request.Table, request.Chain)
	if err != nil {
		logger.Error("Failed to flush iptables chain", zap.Error(err), zap.Any("request", request))
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	logger.Info("Flushed iptables chain", zap.Any("request", request))
	c.JSON(http.StatusOK, gin.H{"status": "success", "message": fmt.Sprintf("Chain %s in table %s flushed successfully", request.Chain, request.Table)})
}

func getRunningProcesses(c *gin.Context) {
	processes, err := process.Processes()
	if err != nil {
		logger.Error("Failed to get running processes", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	processInfo := make([]map[string]interface{}, 0)
	for _, p := range processes {
		name, _ := p.Name()
		username, _ := p.Username()
		processInfo = append(processInfo, map[string]interface{}{
			"pid":      p.Pid,
			"name":     name,
			"username": username,
		})
	}

	logger.Info("Retrieved running processes", zap.Int("count", len(processInfo)))
	c.JSON(http.StatusOK, processInfo)
}

func addUser(c *gin.Context) {
	var request struct {
		Username string   `json:"username"`
		Password string   `json:"password"`
		Groups   []string `json:"groups"`
	}
	if err := c.ShouldBindJSON(&request); err != nil {
		logger.Error("Failed to bind JSON", zap.Error(err))
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(request.Password), bcrypt.DefaultCost)
	if err != nil {
		logger.Error("Failed to hash password", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to hash password"})
		return
	}

	cmd := exec.Command("useradd", "-m", "-p", string(hashedPassword), request.Username)
	err = cmd.Run()
	if err != nil {
		logger.Error("Failed to add user", zap.Error(err), zap.String("username", request.Username))
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("Failed to add user: %v", err)})
		return
	}

	for _, group := range request.Groups {
		cmd = exec.Command("usermod", "-aG", group, request.Username)
		err = cmd.Run()
		if err != nil {
			logger.Warn("Failed to add user to group", zap.Error(err), zap.String("username", request.Username), zap.String("group", group))
		}
	}

	logger.Info("Added new user", zap.String("username", request.Username), zap.Strings("groups", request.Groups))
	c.JSON(http.StatusOK, gin.H{"message": fmt.Sprintf("User %s added successfully", request.Username)})
}

func removeUser(c *gin.Context) {
	var request struct {
		Username string `json:"username"`
	}
	if err := c.ShouldBindJSON(&request); err != nil {
		logger.Error("Failed to bind JSON", zap.Error(err))
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	cmd := exec.Command("userdel", "-r", request.Username)
	err := cmd.Run()
	if err != nil {
		logger.Error("Failed to remove user", zap.Error(err), zap.String("username", request.Username))
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("Failed to remove user: %v", err)})
		return
	}

	logger.Info("Removed user", zap.String("username", request.Username))
	c.JSON(http.StatusOK, gin.H{"message": fmt.Sprintf("User %s removed successfully", request.Username)})
}

func getInstalledApplications(c *gin.Context) {
	cmd := exec.Command("dpkg", "--get-selections")
	output, err := cmd.Output()
	if err != nil {
		logger.Error("Failed to get installed applications", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("Failed to get installed applications: %v", err)})
		return
	}

	applications := strings.Split(string(output), "\n")
	logger.Info("Retrieved installed applications", zap.Int("count", len(applications)))
	c.JSON(http.StatusOK, gin.H{"applications": applications, "count": len(applications)})
}

func handleWebSocket(c *gin.Context) {
	conn, err := upgrader.Upgrade(c.Writer, c.Request, nil)
	if err != nil {
		logger.Error("Failed to upgrade to WebSocket", zap.Error(err))
		return
	}
	defer conn.Close()

	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()

	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			_, _, err := conn.ReadMessage()
			if err != nil {
				logger.Warn("WebSocket read error", zap.Error(err))
				return
			}
		}
	}()

	for {
		select {
		case <-done:
			return
		case <-ticker.C:
			processes, err := process.Processes()
			if err != nil {
				logger.Error("Failed to get processes", zap.Error(err))
				continue
			}

			processInfo := make([]map[string]interface{}, 0)
			for _, p := range processes {
				name, _ := p.Name()
				username, _ := p.Username()
				processInfo = append(processInfo, map[string]interface{}{
					"pid":      p.Pid,
					"name":     name,
					"username": username,
				})
			}

			data, err := json.Marshal(processInfo)
			if err != nil {
				logger.Error("Failed to marshal process data", zap.Error(err))
				continue
			}

			if err := conn.WriteMessage(websocket.TextMessage, data); err != nil {
				logger.Error("Failed to send WebSocket message", zap.Error(err))
				return
			}
			logger.Info("Sent process data over WebSocket", zap.Int("process_count", len(processInfo)))
		}
	}
}

func main() {
	gin.SetMode(gin.ReleaseMode)
	r := gin.New()
	r.Use(gin.Recovery())
	r.Use(rateLimitMiddleware())

	r.GET("/", func(c *gin.Context) {
		c.String(http.StatusOK, "Agent is running")
	})

	r.POST("/apply-rules", requireAPIKey(), timeout.New(
		timeout.WithTimeout(10*time.Second),
		timeout.WithHandler(applyRules),
	))
	r.GET("/iptables_rules", requireAPIKey(), getIPTablesRules)
	r.POST("/delete_rule", requireAPIKey(), deleteRule)
	r.POST("/flush_chain", requireAPIKey(), flushChain)
	r.GET("/processes", requireAPIKey(), getRunningProcesses)
	r.POST("/add_user", requireAPIKey(), addUser)
	r.POST("/remove_user", requireAPIKey(), removeUser)
	r.GET("/applications", requireAPIKey(), getInstalledApplications)
	r.GET("/ws", handleWebSocket)

	srv := &http.Server{
		Addr:    ":5000",
		Handler: r,
	}

	go func() {
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Fatal("Failed to start server", zap.Error(err))
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit
	logger.Info("Shutting down server...")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		logger.Fatal("Server forced to shutdown", zap.Error(err))
	}

	logger.Info("Server exiting")
}
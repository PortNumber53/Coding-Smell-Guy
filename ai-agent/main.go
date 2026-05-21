package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	_ "github.com/mattn/go-sqlite3"
	"github.com/spf13/viper"
)

// Config holds the application configuration.
type Config struct {
	Port           string `mapstructure:"PORT"`
	GitHubToken    string `mapstructure:"GITHUB_TOKEN"`
	GitLabToken    string `mapstructure:"GITLAB_TOKEN"`
	NVIDIAAPIKey   string `mapstructure:"NVIDIA_API_KEY"`
	AutofixSmells  bool   `mapstructure:"AUTOFIX_SMELLS"`
	AutofixComplex bool   `mapstructure:"AUTOFIX_COMPLEX"`
	AutofixVuln    bool   `mapstructure:"AUTOFIX_VULN"`
	PeriodicInterval int    `mapstructure:"PERIODIC_INTERVAL_MINUTES"` // in minutes
	DBPath         string `mapstructure:"DB_PATH"`
	WebhookSecret    string `mapstructure:"WEBHOOK_SECRET"`
}

// WebhookPayload represents the payload from GitHub/GitLab webhook.
type WebhookPayload struct {
	Action string `json:"action"`
	PullRequest struct {
		ID        int    `json:"id"`
		Number    int    `json:"number"`
		Title     string `json:"title"`
		Head struct {
			Repo struct {
				FullName string `json:"full_name"`
			} `json:"repo"`
			SHA string `json:"sha"`
		} `json:"head"`
		Base struct {
			Repo struct {
				FullName string `json:"full_name"`
			} `json:"repo"`
		} `json:"base"`
	} `json:"pull_request"`
	Repository struct {
		FullName string `json:"full_name"`
	} `json:"repository"`
}

// AnalysisResult represents the result from the LLM analysis.
type AnalysisResult struct {
	Issues []Issue `json:"issues"`
}

// Issue represents a single issue found.
type Issue struct {
	Type       string `json:"type"` // e.g., "code_smell", "complexity", "vulnerability"
	Description string `json:"description"`
	File       string `json:"file"`
	Line       int    `json:"line"`
	Suggestion string `json:"suggestion,omitempty"`
}

var (
	config Config
	db     *sql.DB
)

func main() {
	loadConfig()
	initDB()
	defer db.Close()

	r := gin.Default()

	// Webhook endpoint
	r.POST("/webhook", webhookHandler)

	// Health check
	r.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "ok"})
	})

	// Start periodic analysis if enabled
	if config.PeriodicInterval > 0 {
		go startPeriodicAnalysis()
	}

	// Run server
	addr := fmt.Sprintf(":%s", config.Port)
	log.Printf("Starting server on %s", addr)
	if err := r.Run(addr); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
}

func loadConfig() {
	// Set configuration defaults
	viper.SetDefault("PORT", "8080")
	viper.SetDefault("GITHUB_TOKEN", "")
	viper.SetDefault("GITLAB_TOKEN", "")
	viper.SetDefault("NVIDIA_API_KEY", "")
	viper.SetDefault("AUTOFIX_SMELLS", false)
	viper.SetDefault("AUTOFIX_COMPLEX", false)
	viper.SetDefault("AUTOFIX_VULN", false)
	viper.SetDefault("PERIODIC_INTERVAL_MINUTES", 0)
	viper.SetDefault("DB_PATH", "./coding_smell_agent.db")
	viper.SetDefault("WEBHOOK_SECRET", "")

	// Read .env file from current directory (if exists)
	viper.SetConfigType("env")
	viper.SetConfigName(".env") // looks for .env file
	viper.AddConfigPath(".")    // current directory
	if err := viper.MergeInConfig(); err == nil {
		log.Printf("Loaded .env file")
	} else {
		// It's okay if .env file doesn't exist
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
			log.Printf("WARNING: Error reading .env file: %v", err)
		}
	}

	// Read config file from $HOME/.config/coding-smell-guy/config.ini (or .json, .yaml, etc.)
	home, err := os.UserHomeDir()
	if err != nil {
		log.Printf("WARNING: Could not get home directory: %v", err)
	} else {
		configFile := filepath.Join(home, ".config", "coding-smell-guy", "config.ini")
		// Try to read the config file, but continue if not found
		if _, err := os.Stat(configFile); err == nil {
			viper.SetConfigFile(configFile)
			viper.SetConfigType("env") // The file is in .env format (KEY=VALUE)
			if err := viper.ReadInConfig(); err == nil {
				log.Printf("Using config file: %s", viper.ConfigFileUsed())
			} else {
				log.Printf("WARNING: Error reading config file: %v", err)
			}
		} else {
			log.Printf("Config file not found: %s", configFile)
		}
	}

	// Read environment variables (overrides everything)
	viper.AutomaticEnv()
	// No need to set EnvKeyReplacer because we are using uppercase keys with underscores in the mapstructure tags.
	// AutomaticEnv will look for environment variables that match the key in uppercase.
	// Since our keys in viper are uppercase (e.g., "NVIDIA_API_KEY"), the environment variable should be the same.

	// Unmarshal into config struct
	if err := viper.Unmarshal(&config); err != nil {
		log.Fatalf("Unable to decode config into struct: %v", err)
	}

	// Validate required config
	if config.NVIDIAAPIKey == "" {
		log.Fatal("NVIDIA_API_KEY is required")
	}
	if config.GitHubToken == "" && config.GitLabToken == "" {
		log.Printf("WARN: At least one of GITHUB_TOKEN or GITLAB_TOKEN should be set for PR commenting")
	}
}

func getEnv(key, fallback string) string {
	if value, exists := os.LookupEnv(key); exists {
		return value
	}
	return fallback
}

func getEnvAsBool(key string, fallback bool) bool {
	if value, exists := os.LookupEnv(key); exists {
		return value == "true" || value == "1" || value == "t" || value == "T"
	}
	return fallback
}

func getEnvAsInt(key string, fallback int) int {
	if value, exists := os.LookupEnv(key); exists {
		var v int
		fmt.Sscanf(value, "%d", &v)
		return v
	}
	return fallback
}

func initDB() {
	var err error
	db, err = sql.Open("sqlite3", config.DBPath)
	if err != nil {
		log.Fatalf("Failed to open database: %v", err)
	}

	// Create table for tracking verified files
	createTableSQL := `
	CREATE TABLE IF NOT EXISTS verified_files (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		repo_full_name TEXT NOT NULL,
		file_path TEXT NOT NULL,
		commit_sha TEXT NOT NULL,
		last_verified TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
		UNIQUE(repo_full_name, file_path, commit_sha)
	);
	`
	if _, err := db.Exec(createTableSQL); err != nil {
		log.Fatalf("Failed to create table: %v", err)
	}
}

func webhookHandler(c *gin.Context) {
	// Webhook secret check (GitHub HMAC validation)
	if config.WebhookSecret != "" {
		signature := c.GetHeader("X-Hub-Signature-256")
		if signature == "" {
			// Fallback to X-Hub-Signature for SHA1
			signature = c.GetHeader("X-Hub-Signature")
		}
		
		if signature == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Missing X-Hub-Signature header"})
			return
		}
		
		// Get the request body
		payload, err := c.GetRawData()
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Could not read request body"})
			return
		}
		log.Printf("DEBUG: Received webhook payload length: %d", len(payload))
		if len(payload) > 0 {
			log.Printf("DEBUG: Payload first 20 bytes hex: %x", payload[:min(20, len(payload))])
			log.Printf("DEBUG: Payload last 20 bytes hex: %x", payload[max(0, len(payload)-20):])
		}
		log.Printf("DEBUG: Webhook secret length: %d", len(config.WebhookSecret))
		log.Printf("DEBUG: Webhook secret (first 10 chars): %s", string([]byte(config.WebhookSecret)[:min(10, len(config.WebhookSecret))]))
		log.Printf("DEBUG: Webhook secret (full): %q", config.WebhookSecret)
		log.Printf("DEBUG: Webhook secret length: %d", len(config.WebhookSecret))
		log.Printf("DEBUG: Webhook secret bytes: %x", []byte(config.WebhookSecret))
		log.Printf("DEBUG: Signature header: %s", signature)
		
		// Validate the HMAC
		var isValid bool
		var providedHex string
		var expectedHex string
		if strings.HasPrefix(signature, "sha256=") {
			providedHex = strings.TrimPrefix(signature, "sha256=")
			mac := hmac.New(sha256.New, []byte(config.WebhookSecret))
			mac.Write(payload)
			expectedHex = hex.EncodeToString(mac.Sum(nil))
			isValid = hmac.Equal([]byte(expectedHex), []byte(providedHex))
			log.Printf("DEBUG: Webhook SHA256 signature validation. Provided: %s, Expected: %s", providedHex, expectedHex)
			log.Printf("DEBUG: Payload length: %d", len(payload))
			if len(payload) < 200 {
				log.Printf("DEBUG: Payload: %s", string(payload))
			} else {
				log.Printf("DEBUG: Payload first 100 bytes: %s", string(payload[:100]))
				log.Printf("DEBUG: Payload last 100 bytes: %s", string(payload[len(payload)-100:]))
			}
		} else if strings.HasPrefix(signature, "sha1=") {
			providedHex = strings.TrimPrefix(signature, "sha1=")
			mac := hmac.New(sha1.New, []byte(config.WebhookSecret))
			mac.Write(payload)
			expectedHex = hex.EncodeToString(mac.Sum(nil))
			isValid = hmac.Equal([]byte(expectedHex), []byte(providedHex))
			log.Printf("DEBUG: Webhook SHA1 signature validation. Provided: %s, Expected: %s", providedHex, expectedHex)
			log.Printf("DEBUG: Payload length: %d", len(payload))
			if len(payload) < 200 {
				log.Printf("DEBUG: Payload: %s", string(payload))
			} else {
				log.Printf("DEBUG: Payload first 100 bytes: %s", string(payload[:100]))
				log.Printf("DEBUG: Payload last 100 bytes: %s", string(payload[len(payload)-100:]))
			}
		} else {
			log.Printf("ERROR: Invalid signature format: %s", signature)
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid signature format"})
			return
		}
		
		log.Printf("DEBUG: HMAC validation result: %v", isValid)
		if !isValid {
			log.Printf("DEBUG: Computed MAC: %s", expectedHex)
			log.Printf("DEBUG: Provided MAC: %s", providedHex)
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid signature"})
			return
		}
		
		// Reset the body for later use
		c.Request.Body = io.NopCloser(bytes.NewBuffer(payload))
	}

	var payload WebhookPayload
	if err := c.ShouldBindJSON(&payload); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid payload"})
		return
	}

	// We only care about PR opened events
	if payload.Action != "opened" {
		c.JSON(http.StatusOK, gin.H{"message": "Ignoring non-opened event"})
		return
	}

	// Determine which platform (GitHub or GitLab) based on tokens or payload structure.
	// For simplicity, we assume GitHub if GitHubToken is set, else GitLab.
	// In a real implementation, you might check the User-Agent or other headers.
	platform := "github"
	if config.GitHubToken == "" && config.GitLabToken != "" {
		platform = "gitlab"
	}

	// Analyze the PR
	log.Printf("INFO: Starting PR analysis for platform %s", platform)
	go analyzePR(payload, platform)

	c.JSON(http.StatusOK, gin.H{"message": "PR analysis started"})
}

func analyzePR(payload WebhookPayload, platform string) {
	var err error
	switch platform {
	case "github":
		err = analyzePRGitHub(payload)
	case "gitlab":
		err = analyzePRGitLab(payload)
	default:
		err = fmt.Errorf("unsupported platform: %s", platform)
	}
	if err != nil {
		log.Printf("ERROR: Error analyzing PR: %v", err)
	} else {
		log.Printf("INFO: PR analysis completed for platform %s", platform)
	}
}

// analyzePRGitHub analyzes a GitHub pull request.
func analyzePRGitHub(payload WebhookPayload) error {
	owner := payload.Repository.FullName // format: owner/repo
	repo := strings.SplitN(owner, "/", 2)
	if len(repo) != 2 {
		return fmt.Errorf("invalid repository full name: %s", owner)
	}
	ownerName := repo[0]
	repoName := repo[1]
	prNumber := payload.PullRequest.Number
	headSHA := payload.PullRequest.Head.SHA

	// Get list of files in the PR
	files, err := getPRFilesGitHub(ownerName, repoName, prNumber)
	if err != nil {
		return fmt.Errorf("failed to get PR files: %v", err)
	}

	for _, file := range files {
		// Skip if file is deleted
		if file.Status == "removed" {
			continue
		}

		// Check if we have already verified this file at this commit
		verified, err := isFileVerified(owner+"/"+repoName, file.Filename, headSHA)
		if err != nil {
			log.Printf("Error checking verification status for %s: %v", file.Filename, err)
			continue
		}
		if verified {
			log.Printf("File %s already verified at commit %s, skipping", file.Filename, headSHA)
			continue
		}

		// Get file content
		content, err := getFileContentGitHub(ownerName, repoName, file.Filename, headSHA)
		if err != nil {
			log.Printf("Error getting content for %s: %v", file.Filename, err)
			continue
		}

		// Analyze with LLM
		log.Printf("INFO: Analyzing file %s with LLM (%d bytes)", file.Filename, len(content))
		analysis, err := analyzeFileWithLLM(content)
		if err != nil {
			log.Printf("ERROR: Failed to analyze file %s: %v", file.Filename, err)
			continue
		}
		log.Printf("INFO: LLM analysis complete for %s. Found %d issues", file.Filename, len(analysis.Issues))

		// Filter issues by type if needed (we could also filter based on autofix flags, but we'll report all)
		var issuesToReport []Issue
		for _, issue := range analysis.Issues {
			// We can skip certain types if autofix is disabled? No, we still want to report.
			issuesToReport = append(issuesToReport, issue)
		}

		if len(issuesToReport) > 0 {
			// Post a comment on the PR with the issues
			err := postPRCommentGitHub(ownerName, repoName, prNumber, file.Filename, issuesToReport)
			if err != nil {
				log.Printf("Error posting comment for %s: %v", file.Filename, err)
			}

			// If autofix is enabled for any issue type, attempt to create a fix commit
			if config.AutofixSmells || config.AutofixComplex || config.AutofixVuln {
				go attemptAutofixGitHub(ownerName, repoName, file.Filename, content, issuesToReport, headSHA)
			}
		}

		// Mark file as verified
		err = markFileVerified(owner+"/"+repoName, file.Filename, headSHA)
		if err != nil {
			log.Printf("Error marking file %s as verified: %v", file.Filename, err)
		}
	}

	return nil
}

// analyzePRGitLab analyzes a GitLab merge request (placeholder).
func analyzePRGitLab(payload WebhookPayload) error {
	// TODO: Implement GitLab MR analysis similar to GitHub
	log.Printf("GitLab support not yet implemented")
	return nil
}

// getPRFilesGitHub fetches the list of files in a GitHub PR.
func getPRFilesGitHub(owner, repo string, prNumber int) ([]GitHubFile, error) {
	endpoint := fmt.Sprintf("https://api.github.com/repos/%s/%s/pulls/%d/files", owner, repo, prNumber)
	req, err := http.NewRequest("GET", endpoint, nil)
	if err != nil {
		return nil, err
	}
	if config.GitHubToken != "" {
		req.Header.Set("Authorization", "token "+config.GitHubToken)
	}
	req.Header.Set("Accept", "application/vnd.github.v3+json")

	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GitHub API returned status %d", resp.StatusCode)
	}

	var files []GitHubFile
	if err := json.NewDecoder(resp.Body).Decode(&files); err != nil {
		return nil, err
	}
	return files, nil
}

// GitHubFile represents a file in a GitHub PR.
type GitHubFile struct {
	Filename string `json:"filename"`
	Status   string `json:"status"` // added, removed, modified, renamed
	// Add other fields if needed
}

// getFileContentGitHub fetches the content of a file at a specific commit SHA.
func getFileContentGitHub(owner, repo, filename, commitSHA string) (string, error) {
	// Use the contents API to get the file content at the given commit
	endpoint := fmt.Sprintf("https://api.github.com/repos/%s/%s/contents/%s?ref=%s", owner, repo, url.PathEscape(filename), commitSHA)
	req, err := http.NewRequest("GET", endpoint, nil)
	if err != nil {
		return "", err
	}
	if config.GitHubToken != "" {
		req.Header.Set("Authorization", "token "+config.GitHubToken)
	}
	req.Header.Set("Accept", "application/vnd.github.v3+json")

	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("GitHub API returned status %d for file %s", resp.StatusCode, filename)
	}

	var respBody struct {
		Content string `json:"content"`
		Encoding string `json:"encoding"` // usually "base64"
	}
	if err := json.NewDecoder(resp.Body).Decode(&respBody); err != nil {
		return "", err
	}

	if respBody.Encoding == "base64" {
		decoded, err := base64Decode(respBody.Content)
		if err != nil {
			return "", err
		}
		return string(decoded), nil
	}
	return respBody.Content, nil
}

// base64Decode decodes a base64 string.
func base64Decode(s string) ([]byte, error) {
	return io.ReadAll(base64.NewDecoder(base64.StdEncoding, strings.NewReader(s)))
}

// postPRCommentGitHub posts a comment on a PR with the list of issues.
func postPRCommentGitHub(owner, repo string, prNumber int, filename string, issues []Issue) error {
	// Create a comment body
	var buf strings.Builder
	buf.WriteString(fmt.Sprintf("### Code Analysis for `%s`\n\n", filename))
	buf.WriteString("Found the following issues:\n\n")
	for _, issue := range issues {
		buf.WriteString(fmt.Sprintf("- **%s** (line %d): %s\n", issue.Type, issue.Line, issue.Description))
		if issue.Suggestion != "" {
			buf.WriteString(fmt.Sprintf("  - Suggestion: %s\n", issue.Suggestion))
		}
	}
	buf.WriteString("\n---\n*Analysis performed by Coding Smell Agent*")

	comment := map[string]string{
		"body": buf.String(),
	}
	payloadBytes, err := json.Marshal(comment)
	if err != nil {
		return err
	}

	endpoint := fmt.Sprintf("https://api.github.com/repos/%s/%s/issues/%d/comments", owner, repo, prNumber)
	req, err := http.NewRequest("POST", endpoint, bytes.NewReader(payloadBytes))
	if err != nil {
		return err
	}
	if config.GitHubToken != "" {
		req.Header.Set("Authorization", "token "+config.GitHubToken)
	}
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		return fmt.Errorf("GitHub API returned status %d", resp.StatusCode)
	}
	return nil
}

// attemptAutofixGitHub attempts to create a commit with fixes for the given issues.
// This is a placeholder; actual implementation would involve generating code changes.
func attemptAutofixGitHub(owner, repo, filename, originalContent string, issues []Issue, baseSHA string) {
	log.Printf("Attempting autofix for %s (not yet implemented)", filename)
	// TODO:
	// 1. For each issue, generate a fix (maybe by asking the LLM to provide a fix).
	// 2. Apply the fixes to the content.
	// 3. Create a new commit on a branch and open a PR or push directly (depending on permissions).
	// For now, we just log.
}

// isFileVerified checks if a file has been verified at the given commit.
func isFileVerified(repoFullName, filePath, commitSHA string) (bool, error) {
	var exists bool
	err := db.QueryRow("SELECT EXISTS(SELECT 1 FROM verified_files WHERE repo_full_name = ? AND file_path = ? AND commit_sha = ?)", repoFullName, filePath, commitSHA).Scan(&exists)
	return exists, err
}

// markFileVerified records that a file has been verified at the given commit.
func markFileVerified(repoFullName, filePath, commitSHA string) error {
	_, err := db.Exec("INSERT OR IGNORE INTO verified_files (repo_full_name, file_path, commit_sha) VALUES (?, ?, ?)", repoFullName, filePath, commitSHA)
	return err
}

// startPeriodicAnalysis runs periodic analysis of the codebase (placeholder).
func startPeriodicAnalysis() {
	ticker := time.NewTicker(time.Duration(config.PeriodicInterval) * time.Minute)
	defer ticker.Stop()
	for range ticker.C {
		log.Println("Starting periodic analysis")
		// TODO: Implement periodic analysis of repositories (maybe from a config list)
	}
}

// analyzeFileWithLLM sends the file content to the NVIDIA API and returns analysis.
func analyzeFileWithLLM(content string) (AnalysisResult, error) {
	// We'll ask the LLM to analyze the code for code smells, complexity, and vulnerabilities.
	// We'll structure the prompt to get a JSON response.
	prompt := fmt.Sprintf(`You are an expert code reviewer. Analyze the following code for:
1. Code smells (e.g., duplicated code, long methods, large classes, etc.)
2. Complexity (e.g., cyclomatic complexity, nested conditionals, etc.)
3. Security vulnerabilities (e.g., SQL injection, buffer overflows, etc.)

For each issue found, provide:
- Type: one of "code_smell", "complexity", "vulnerability"
- Description: a clear description of the issue
- File: the file name (we will fill this in later, but you can leave it as empty or guess from context)
- Line: the line number where the issue occurs (approximate if needed)
- Suggestion: a suggestion on how to fix the issue (optional)

Return a JSON object with an "issues" array containing the issues found.
If no issues are found, return an empty array.

Code:
%s`, content)

	invokeURL := "https://integrate.api.nvidia.com/v1/chat/completions"
	payload := map[string]interface{}{
		"model": "moonshotai/kimi-k2.6",
		"messages": []map[string]string{
			{"role": "user", "content": prompt},
		},
		"max_tokens": 16384,
		"temperature": 1.00,
		"top_p": 1.00,
		"stream": false,
		"chat_template_kwargs": map[string]bool{"thinking": true},
	}

	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return AnalysisResult{}, err
	}

	req, err := http.NewRequest("POST", invokeURL, bytes.NewReader(payloadBytes))
	if err != nil {
		return AnalysisResult{}, err
	}
	req.Header.Set("Authorization", "Bearer "+config.NVIDIAAPIKey)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json")

	maxRetries := 3
	var resp *http.Response
	var requestErr error
	
	for i := 0; i <= maxRetries; i++ {
		client := &http.Client{Timeout: 60 * time.Second} // Longer timeout for LLM
		resp, requestErr = client.Do(req)
		if requestErr == nil {
			break // Success, exit retry loop
		}
		
		// If we've exhausted retries, return the error
		if i == maxRetries {
			return AnalysisResult{}, fmt.Errorf("failed after %d retries: %v", maxRetries, requestErr)
		}
		
		// Wait before retrying with exponential backoff
		waitTime := time.Duration(1<<i) * time.Second // 1s, 2s, 4s
		log.Printf("WARNING: NVIDIA API request failed (attempt %d/%d): %v. Retrying in %v...", i+1, maxRetries+1, requestErr, waitTime)
		time.Sleep(waitTime)
	}
	
	// If we exited the loop due to max retries, requestErr will be set
	if requestErr != nil {
		return AnalysisResult{}, requestErr
	}
	
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return AnalysisResult{}, fmt.Errorf("NVIDIA API returned status %d", resp.StatusCode)
	}

	var result map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return AnalysisResult{}, err
	}

	// Extract the content from the response
	contentStr, ok := result["choices"].([]interface{})[0].(map[string]interface{})["message"].(map[string]interface{})["content"].(string)
	if !ok {
		log.Printf("ERROR: Unexpected response format from NVIDIA API: %v", result)
		return AnalysisResult{}, fmt.Errorf("unexpected response format")
	}

	// Log the raw response for debugging
	log.Printf("INFO: Raw LLM response: %s", contentStr)

	// Parse the contentStr as JSON (expected to be AnalysisResult)
	var analysis AnalysisResult
	if err := json.Unmarshal([]byte(contentStr), &analysis); err != nil {
		// If the LLM didn't return JSON, we might want to wrap it.
		log.Printf("WARNING: LLM did not return valid JSON: %v. Error: %v", contentStr, err)
		analysis.Issues = []Issue{{
			Type:       "note",
			Description: contentStr,
		}}
	}

	return analysis, nil
}
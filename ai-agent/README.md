# Coding Smell Agent

An AI agent that reviews pull requests for code smells, complexity, and vulnerabilities using LLMs on NVIDIA's cloud infrastructure.

## Features

- Webhook endpoint for GitHub and GitLab pull request events
- Analyzes code using NVIDIA's LLM API (moonshotai/kimi-k2.6)
- Reports issues as comments on pull requests
- Optional autofix for different issue categories
- Local SQLite database to track verified files and avoid re-analysis
- Periodic analysis of codebases (configurable)
- Docker support for easy deployment

## Requirements

- Go 1.22+ (for building from source)
- Docker (for containerized deployment)
- NVIDIA API key (set as `NVIDIA_API_KEY` environment variable)
- GitHub token (set as `GITHUB_TOKEN`) and/or GitLab token (set as `GITLAB_TOKEN`) for PR commenting

## Configuration

The agent is configured via environment variables:

| Variable | Description | Default |
|----------|-------------|---------|
| `PORT` | Port to listen on | `8080` |
| `GITHUB_TOKEN` | GitHub personal access token | (empty) |
| `GITLAB_TOKEN` | GitLab personal access token | (empty) |
| `NVIDIA_API_KEY` | NVIDIA API key for LLM access | **required** |
| `AUTOFIX_SMELLS` | Enable autofix for code smells | `false` |
| `AUTOFIX_COMPLEX` | Enable autofix for complexity issues | `false` |
| `AUTOFIX_VULN` | Enable autofix for vulnerabilities | `false` |
| `PERIODIC_INTERVAL_MINUTES` | Interval for periodic analysis (0 to disable) | `0` |
| `DB_PATH` | Path to SQLite database file | `./coding_smell_agent.db` |

## Running the Agent

### From Source

```bash
# Clone the repository
git clone <repository-url>
cd ai-agent

# Install dependencies
go mod download

# Build
go build -o coding-smell-agent .

# Run with required environment variables
NVIDIA_API_KEY=your_nvidia_key GITHUB_TOKEN=your_github_token ./coding-smell-agent
```

### With Docker

```bash
# Build the Docker image
docker build -t coding-smell-agent .

# Run the container
docker run -d \
  -p 8080:8080 \
  -e NVIDIA_API_KEY=your_nvidia_key \
  -e GITHUB_TOKEN=your_github_token \
  -e AUTOFIX_SMELLS=true \
  -e PERIODIC_INTERVAL_MINUTES=60 \
  --name coding-smell-agent \
  coding-smell-agent
```

## Webhook Setup

### GitHub

1. Go to your repository Settings > Webhooks > Add webhook
2. Payload URL: `http://your-server-host:8080/webhook`
3. Content type: `application/json`
4. Secret: (optional, but recommended for security)
5. Which events: Select "Pull requests"

### GitLab

1. Go to your project Settings > Webhooks > Add new webhook
2. URL: `http://your-server-host:8080/webhook`
3. Secret Token: (optional, but recommended)
4. Trigger: Select "Merge request events"

## How It Works

1. When a pull request is opened, the agent receives a webhook event.
2. For each file in the PR:
   - Checks if the file has already been analyzed at the current commit SHA (using SQLite database)
   - If not analyzed, fetches the file content
   - Sends the content to the NVIDIA LLM with a prompt to identify code smells, complexity issues, and vulnerabilities
   - Posts a comment on the PR with the findings
   - If autofix is enabled for any category, attempts to generate fixes (placeholder)
   - Marks the file as verified in the database
3. Periodic analysis (if enabled) runs at the specified interval to analyze repositories (to be implemented).

## Limitations

- GitLab support is currently a placeholder and needs implementation.
- Autofix functionality is a placeholder and needs implementation.
- Periodic analysis of arbitrary repositories needs implementation (could read from a config file or database).

## Contributing

Feel free to submit issues and pull requests!

## License

MIT
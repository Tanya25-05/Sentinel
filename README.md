# SENTINEL - AI-Powered Isolated Security Testing Platform

SENTINEL is a production-grade security testing platform that clones repositories into isolated environments, performs automated security analysis, and uses AI to prioritize vulnerabilities and generate remediations.

## Features

- **Isolated Execution**: Uses Docker and Firecracker microVMs for secure scanning
- **Comprehensive Analysis**: Detects vulnerabilities from traditional hackers, malicious AI agents, prompt injection, insecure MCP/tool usage, unsafe APIs, authentication flaws, dependency exploits, business logic issues, SSRF, RCE, XSS, SQL injection, insecure deserialization, and supply-chain attacks
- **AI-Powered Analysis**: Uses Ollama with Llama 3.2 for vulnerability prioritization, attack chain reasoning, exploit simulation, and secure code rewrites
- **Industry Tools Integration**: Semgrep, Trivy, CodeQL, Bandit, OWASP ZAP, dependency scanners
- **Modular Architecture**: Frontend dashboard, scanning orchestrator, AI reasoning engine, vulnerability database, remediation engine, reporting layer
- **Zero Modification**: Original repositories remain untouched
- **Audit Logging**: Complete audit trail of all operations
- **Scalable**: Concurrent scans with Redis queue

## Architecture

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Next.js       │    │   FastAPI       │    │   PostgreSQL    │
│   Frontend      │◄──►│   Backend       │◄──►│   Database      │
│   Dashboard     │    │   API           │    │                 │
└─────────────────┘    └─────────────────┘    └─────────────────┘
         │                       │                       │
         ▼                       ▼                       ▼
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Docker        │    │   Redis Queue   │    │   Ollama        │
│   Containers    │    │                 │    │   AI Engine     │
│   (Scanning)    │    │                 │    │   (Llama 3.2)   │
└─────────────────┘    └─────────────────┘    └─────────────────┘
```

## Quick Start

### Prerequisites

- Docker and Docker Compose
- Git
- Node.js 20+ (for local development)
- Python 3.12+ (for local development)

### Using Docker Compose (Recommended)

1. Clone the repository:

```bash
git clone <repository-url>
cd sentinel
```

2. Copy environment file:

```bash
cp .env.example .env
```

3. Edit `.env` with your configuration (database credentials, etc.)

4. Start the services:

```bash
docker-compose up --build
```

5. Access the application:

- Frontend: http://localhost:3000
- Backend API: http://localhost:8000
- API Docs: http://localhost:8000/docs

### Local Development

1. Backend setup:

```bash
cd backend
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
pip install -r requirements.txt
python main.py
```

2. Frontend setup:

```bash
cd src
npm install
npm run dev
```

3. Database setup:

```bash
# Install PostgreSQL locally or use Docker
docker run -d --name postgres -p 5432:5432 -e POSTGRES_DB=sentinel -e POSTGRES_USER=sentinel -e POSTGRES_PASSWORD=sentinel postgres:15
```

4. Redis setup:

```bash
docker run -d --name redis -p 6379:6379 redis:7-alpine
```

5. Ollama setup:

```bash
# Install Ollama: https://ollama.ai/
ollama pull llama3.2
ollama serve
```

## API Usage

### Start a Scan

```bash
curl -X POST http://localhost:8000/api/scans/ \
  -H "Content-Type: application/json" \
  -d '{"repo_url": "https://github.com/owner/repo", "branch": "main"}'
```

### Get Scan Results

```bash
curl http://localhost:8000/api/scans/{scan_id}
```

### Generate Report

```bash
curl -X POST http://localhost:8000/api/reports/{scan_id}?format=pdf
```

## Security Model

- **Isolation**: All scans run in ephemeral Docker containers
- **No Persistence**: Scanned repositories are deleted after analysis
- **Access Control**: API endpoints require authentication (implement JWT)
- **Audit Logging**: All operations are logged with timestamps and user context
- **Input Validation**: All inputs are validated and sanitized
- **Rate Limiting**: Redis-based rate limiting on API endpoints

## Threat Mitigation

- **Container Escape**: Docker containers run as non-root users with limited capabilities
- **Network Isolation**: Containers have no internet access during scanning
- **Resource Limits**: CPU and memory limits prevent DoS attacks
- **Secrets Detection**: Gitleaks scans for hardcoded credentials
- **AI Safety**: Ollama runs in isolated container with no external network access

## Scaling

### Horizontal Scaling

- **Backend**: Run multiple FastAPI instances behind a load balancer
- **Workers**: Use Redis queue for distributed scanning workers
- **Database**: PostgreSQL read replicas for high availability

### Vertical Scaling

- **Memory**: Increase container memory limits for large repositories
- **CPU**: Allocate more CPU cores for parallel scanning
- **Storage**: Use distributed storage for scan artifacts

## Cost Optimization

### Free/Open-Source Alternatives

- **AI Engine**: Ollama with Llama 3.2 (free, local)
- **Database**: PostgreSQL (free)
- **Queue**: Redis (free)
- **Container Runtime**: Docker (free)
- **Security Tools**: Semgrep, Bandit, Trivy (free)

### Cloud Costs

- **Compute**: ~$0.10/hour per scan worker
- **Storage**: ~$0.02/GB/month for reports
- **Database**: ~$0.10/hour for PostgreSQL
- **Network**: Minimal egress costs

## MVP Roadmap

1. **Week 1-2**: Core scanning pipeline with Docker isolation
2. **Week 3-4**: AI analysis integration with Ollama
3. **Week 5-6**: Frontend dashboard and reporting
4. **Week 7-8**: Security hardening and audit logging
5. **Week 9-10**: Performance optimization and scaling

## Production Deployment

### Infrastructure Requirements

- **Kubernetes**: For container orchestration
- **Load Balancer**: Nginx or AWS ALB
- **Database**: Managed PostgreSQL (RDS/Aurora)
- **Cache**: Redis cluster
- **Storage**: S3-compatible object storage
- **Monitoring**: Prometheus + Grafana
- **Logging**: ELK stack

### Security Hardening

- **Secrets Management**: HashiCorp Vault or AWS Secrets Manager
- **Network Security**: VPC isolation, security groups
- **Compliance**: SOC 2, ISO 27001 certifications
- **Backup**: Automated database backups with encryption
- **Disaster Recovery**: Multi-region deployment

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests
5. Submit a pull request

## License

MIT License - see LICENSE file for details

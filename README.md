
# AegisFA

**AI-Powered Forensic Assistant for Security Operations Centers**
<p align="center">
  <img src="frontend/src/assets/A.png" alt="AegisFA logo" width="160">
</p>
AegisFA is an AI-assisted security analysis platform that helps SOC analysts investigate security events through log analysis, threat classification, event correlation, and MITRE ATT&CK mapping.

## Features

- Multi-format log ingestion with automatic source detection.
- Machine-learning threat classification using Random Forest.
- Configurable rule-based event correlation.
- MITRE ATT&CK technique mapping using retrieval-augmented generation (RAG).
- AI-generated threat insights, investigation guides, and remediation plans.
- Incident management and collaborative workflows.
- Organization-based access control and background analysis jobs.

## Technology Stack

| Component | Technologies |
|---|---|
| Frontend | React 18, Vite 5 |
| Backend | Python 3.11, Flask 3.1, Gunicorn |
| Database | Supabase, PostgreSQL, pgvector |
| AI | scikit-learn, OpenAI API |
| Deployment | Docker Compose |

## Getting Started

### Prerequisites

- Docker Engine and Docker Compose v2
- A Supabase project
- An OpenAI API key
- A GitHub OAuth application

### Installation

Clone the repository:

```bash
git clone https://github.com/jbvillegas/AegisFA.git
cd AegisFA
```

Configure the required environment variables in:

- `backend/.env`
- `frontend/.env`

See the [environment configuration](#environment-configuration) below.

Apply the SQL migrations in `database/` to your Supabase project in numerical order.

Start the application:

```bash
docker-compose up --build
```

Access the application:

- Frontend: http://localhost:3000
- Backend: http://localhost:5001
- API documentation: http://localhost:5001/docs

Stop the application:

```bash
docker-compose down
```

## Environment Configuration

**`backend/.env`**

```env
SUPABASE_URL=https://your-project.supabase.co
SUPABASE_SERVICE_ROLE_KEY=your-service-role-key
OPENAI_API_KEY=your-openai-api-key
```

**`frontend/.env`**

```env
VITE_SUPABASE_URL=https://your-project.supabase.co
VITE_SUPABASE_ANON_KEY=your-anon-key
VITE_API_BASE_URL=http://localhost:5001
```

Never commit credentials or API keys to the repository.

## Usage

1. Sign in using GitHub OAuth.
2. Upload a supported log file.
3. Review threat classifications, correlated events, and MITRE ATT&CK matches.
4. Explore AI-generated investigation guidance and remediation recommendations.
5. Create incidents and assign tasks in the collaborative workspace.

## Machine Learning

The Random Forest classifier is trained on the [CICIDS2017](https://www.unb.ca/cic/datasets/ids-2017.html) and [CICIDS2019](https://www.unb.ca/cic/datasets/ids-2019.html) datasets.

The project reports a weighted precision of 91.5% on its held-out test set. Performance on real-world security logs may differ.

## Limitations

- Analysis is file-based; real-time streaming is not supported.
- AI-generated outputs require analyst validation.
- Automated remediation execution is not supported.
- An independent security audit has not been performed.

## Contributing

Contributions are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

Report bugs and request features through [GitHub Issues](https://github.com/jbvillegas/AegisFA/issues).

## License

Distributed under the [MIT License](LICENSE).

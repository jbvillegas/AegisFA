# AegisFA

**AI-Powered Forensic Assistant for Security Operations Centers**

<p align="center">
  <img src="frontend/src/assets/A.png" alt="Project Logo" width="200" height="200">
</p>

AegisFA is an AI-assisted security analysis platform that helps SOC analysts investigate security events through automated log processing, threat classification, event correlation, and MITRE ATT&CK mapping.

## Features

- **Log analysis:** Supports CSV, JSON, NDJSON, and plain text files, including chunked uploads up to 2 GB.
- **Threat classification:** Random Forest model trained on CICIDS2017/2019 datasets.
- **Event correlation:** Configurable rules for identifying suspicious activity.
- **MITRE ATT&CK mapping:** Retrieval-augmented generation (RAG) for matching threats to known techniques.
- **AI-assisted investigation:** Generates threat insights, incident summaries, investigation guides, and remediation plans.
- **Incident management:** Collaborative workspace for incidents, tasks, and event tracking.
- **Multi-tenant access control:** Organization-scoped data access with role-based permissions.

## Architecture

AegisFA consists of three main components:

| Component | Technologies |
|---|---|
| Frontend | React 18, Vite 5 |
| Backend | Python 3.11, Flask 3.1 |
| Database and services | Supabase, PostgreSQL, pgvector |

The analysis pipeline combines machine learning, rule-based correlation, semantic retrieval, and LLM-generated insights.

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

Create the environment files:

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

Apply the SQL migrations in `database/` to your Supabase project, in numerical order.

Build and start the application:

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

## Usage

1. Sign in using GitHub OAuth.
2. Upload a supported log file.
3. Review the analysis results, including threat classifications, correlated events, and MITRE ATT&CK mappings.
4. Explore AI-generated investigation guidance and remediation recommendations.
5. Manage incidents and assign tasks through the collaborative workspace.

## Machine Learning

The Random Forest classifier is trained on the [CICIDS2017](https://www.unb.ca/cic/datasets/ids-2017.html) and [CICIDS2019](https://www.unb.ca/cic/datasets/ids-2019.html) datasets.

The project reports a weighted precision of 91.5% on its held-out test set. Performance on real-world security logs may differ.

## Security

AegisFA uses JWT authentication, role-based access control, organization-scoped authorization, and PostgreSQL Row-Level Security (RLS).

**Security considerations:**

- Keep all service-role keys and API credentials private.
- Do not upload sensitive forensic data to public environments.
- Review authorization policies before deployment.
- An independent security audit has not been performed.

## Limitations

- Analysis is currently file-based; real-time streaming is not supported.
- AI-generated outputs may vary and require analyst validation.
- Automated remediation execution is not supported.
- The project does not currently include a comprehensive automated regression test suite.

## Contributing

Contributions are welcome. Please review the [Contributing Guidelines](CONTRIBUTING.md) before submitting changes.

Report bugs and request features through [GitHub Issues](https://github.com/jbvillegas/AegisFA/issues).

## License

Distributed under the [MIT License](LICENSE).

---

**Developed by [Joaquin Baltasar Villegas](https://github.com/jbvillegas)**

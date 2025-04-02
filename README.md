# 🛡️ AWS WAF Rule Mapper

## 🤔 Why this exists

Managing AWS WAF rules at scale—especially when using **labels** to create complex logic chains—is **hard**.

AWS doesn't provide a native way to visualize which rules **produce** or **consume** labels. This makes it difficult to:

- Understand rule relationships
- Debug unexpected WAF behavior
- Onboard new team members
- Maintain or refactor rule sets

## ✅ What this solves

This tool visualizes your WAF rule interactions based on **label relationships**.

By uploading your AWS WAF JSON rule set, you'll be able to:

- 📈 See which rules produce and consume each label
- 🧭 Trace how rules chain together logically
- 🧠 Understand the entire WAF logic at a glance
- 👥 Share understandable graphs with your team

## 🚀 Getting Started

### 🐳 Run with Docker Compose (recommended)

To avoid polluting your Python environment, run this project inside Docker.

#### 1. Clone the repo

```bash
git clone https://github.com/yourname/aws-waf-mapper.git
cd aws-waf-mapper
```

#### 2. Build and start the container
```bash
docker-compose up --build -d 

#STOP the service 
docker-compose down
```
#### 3. Open the app
Navigate to http://localhost:5001 in your browser.

## 🖼️ Features
- Upload AWS WAF JSON exports
- Auto-parses all rules and extracts label relationships
- Interactive Mermaid.js and Vis.js visualizations
- Trace back rule logic by clicking into each rule

## 🔎 Understanding the Graph
The visual graphs use nodes and arrows to represent WAF rule logic via labels. Here's how to read them:

| Element | Meaning |
|--------|--------|
| **Rule Node** | A named WAF rule (e.g. `BlockMaliciousIP`) |
| **Label Node** | A label that is either produced or matched by rules |
| **→ produces →** | Rule **adds** this label when it matches |
| **→ consumes →** | Rule **matches** requests **with this label** |
| **→ action →** | Shows what the rule **does** when triggered (e.g. Allow, Block) |

### Example:
RuleA -->|produces| Label:GoodTraffic Label:GoodTraffic -->|consumes| RuleB RuleB -->|action| Allow

This means:
- `RuleA` adds a label called `GoodTraffic` when it matches
- `RuleB` looks for that label
- If it finds it, it allows the request

## 📂 Folder Structure
```graphql
.
├── app.py                # Flask web server
├── mapping.py            # Logic to parse and visualize label relationships
├── templates/            # HTML views
├── uploads/              # Stores uploaded JSON files
├── requirements.txt      # Python dependencies
└── docker-compose.yml    # Docker setup (TBD)
```

## 🧪 Sample JSON Input
Your input JSON file should follow the format exported from AWS WAF. It must contain a top-level "Rules" list with each rule's "Name", "RuleLabels" (if any), and "Statement" structure that may include LabelMatchStatement.




# 🧠 ThreatScope – AI-Driven Cyber Threat Intelligence (RAG Engine)

![Python](https://img.shields.io/badge/Python-3.10+-blue)
![Streamlit](https://img.shields.io/badge/Streamlit-App-red)
![ChromaDB](https://img.shields.io/badge/ChromaDB-VectorStore-green)
![MITRE ATT&CK](https://img.shields.io/badge/MITRE-ATT%26CK-orange)
![Ollama](https://img.shields.io/badge/Ollama-Local%20LLMs-blueviolet)
![Status](https://img.shields.io/badge/Project-Active-success)

---

**ThreatScope** is an AI-powered cyber-intelligence assistant that analyzes threat reports, correlates IOCs, extracts threat behaviors, and maps techniques to the MITRE ATT&CK framework — all using a Retrieval-Augmented Generation (RAG) pipeline.

It enables defenders, students, and CTI teams to analyze cyber events quickly using an intuitive **Streamlit UI**, local LLMs (via **Ollama**), and a **ChromaDB** vectorstore.

---

## 🚀 Key Features

- 🔍 **RAG Engine** (Retriever + Generator) for contextual threat intelligence  
- 🎯 **MITRE ATT&CK Mapping** (Techniques, TTPs, behaviors)  
- 📄 **Threat Report Parsing** (PDF, TXT, LOG)  
- 📚 **Semantic Search** with ChromaDB embeddings  
- 💬 **Real-Time Q&A** on all indexed intelligence  
- 🧩 **IOC Extraction & Enrichment**  
- 🖥️ **Interactive Streamlit App**  
- 🔄 **Multiple Model Support:** Qwen, LLaMA3, Ollama local models, etc.  
- 🧪 **Synthetic sample data** for safe experimentation  

---

## 📁 Project Structure

threatscope/
├── app.py # Streamlit UI – main interface
├── rag_engine.py # Core RAG logic
├── data/
│ ├── threat_reports/ # Synthetic threat intelligence samples
│ └── mitre_attack.json # MITRE ATT&CK dataset
├── vectorstore/ # ChromaDB embeddings (synthetic)
├── config/
│ ├── settings.yaml # General configuration
│ └── .env.example # Template for API keys
├── utils/
│ ├── loaders.py # PDF / LOG loaders
│ ├── mitre_parser.py # MITRE technique mapping
│ └── preprocess.py # Chunking + text cleaning
├── requirements.txt
└── README.md


---

## 🔒 Data Disclaimer (Security Notice)

All files inside **`data/threat_reports/`** and all embeddings stored in **`vectorstore/`** are  
**100% synthetic, non-sensitive, and artificially generated**.

They **do not** contain:
- real organizational logs  
- internal cyber incidents  
- production data  
- confidential IOCs  
- any data obtained from an employer  

This repository is safe for public release and intended purely for:
**education, research, and demonstrating RAG-based cyber analysis.**

---

## 🧰 Installation

### 1️⃣ Clone the repository
```bash
git clone https://github.com/YOUR_USERNAME/threatscope.git
cd threatscope

Create a virtual environment
python -m venv venv
source venv/bin/activate      # Linux / Mac
venv\Scripts\activate         # Windows

3️⃣ Install dependencies
pip install -r requirements.txt

4️⃣ Add your environment variables

Create config/.env:

OPENAI_API_KEY=your_key_here
HF_TOKEN=your_token
OLLAMA_HOST=http://localhost:11434


(Only needed if you use OpenAI/HuggingFace.
Local models via Ollama don't require any API keys.)

▶️ Running the Application
streamlit run app.py


The app will open at:
http://localhost:8501

System Architecture
        ┌────────────┐          ┌─────────────────┐
        │ Threat Data │          │ MITRE ATT&CK DB │
        └──────┬─────┘          └─────────┬───────┘
               │ Text / PDF               │
               ▼                           ▼
       ┌─────────────────┐        ┌─────────────────┐
       │ Preprocessing   │        │ MITRE Parser     │
       └──────┬──────────┘        └──────────┬───────┘
              ▼                               ▼
       ┌─────────────────────────────────────────────┐
       │     Embeddings & Vectorstore (ChromaDB)      │
       └───────────────────┬──────────────────────────┘
                           ▼
                 ┌──────────────────┐
                 │    Retriever     │
                 └────────┬─────────┘
                          ▼
                 ┌──────────────────┐
                 │    Generator      │
                 │   (LLM Output)    │
                 └──────────────────┘


 Contributing

Pull requests are welcome!
This project is intentionally simple for learning — improvements such as:

new models

better prompts

more parsers

threat rules

or detection techniques
are encouraged.

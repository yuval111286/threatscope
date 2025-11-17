import os
import re
import json
from langchain_community.embeddings import OllamaEmbeddings
from langchain_community.llms import Ollama
from langchain_community.vectorstores import Chroma
from langchain_text_splitters import RecursiveCharacterTextSplitter
from langchain_community.document_loaders import TextLoader

"""
================================================================================
ThreatRAG — Lightweight Cybersecurity RAG Engine (Professional Edition)
================================================================================

A Retrieval-Augmented Generation engine tailored for cybersecurity analysis.
Uses local threat reports + vector embeddings + contextual LLM reasoning.

Features:
✔ Loads local threat intelligence reports (TXT)
✔ Builds Chroma vectorstore with Ollama embeddings
✔ Retrieves relevant context chunks for each query
✔ Loads custom prompt templates from /prompts
✔ Automatically detects IR / Threat Intel / Hybrid mode
✔ Produces clean JSON output: events, IOC, MITRE, severity, summary
✔ Fully offline — ideal for SOC labs, red/blue teams, and students
================================================================================
"""

class ThreatRAG:
    def __init__(self, data_path="data/threat_reports", db_path="vectorstore"):
        self.data_path = data_path
        self.db_path = db_path

        # Embeddings (local)
        self.embeddings = OllamaEmbeddings(model="nomic-embed-text")

        # Vectorstore instance
        self.vectorstore = None

    # ==========================================================================
    # Index building
    # ==========================================================================
    def build_index(self):
        """Load threat-report TXT files and build the vector database."""
        print("[+] Loading threat reports...")
        docs = []

        for filename in os.listdir(self.data_path):
            if filename.endswith(".txt"):
                loader = TextLoader(os.path.join(self.data_path, filename))
                docs.extend(loader.load())

        splitter = RecursiveCharacterTextSplitter(
            chunk_size=800,
            chunk_overlap=200
        )
        chunks = splitter.split_documents(docs)

        print("[+] Creating vector store...")
        if not os.path.exists(self.db_path):
            os.makedirs(self.db_path)

        self.vectorstore = Chroma.from_documents(
            chunks,
            self.embeddings,
            persist_directory=self.db_path
        )

        self.vectorstore.persist()
        print("[+] Index built successfully.")

    # ==========================================================================
    # Mode detection
    # ==========================================================================
    def detect_mode(self, text):
        """Classify query as IR / Threat Intel / Hybrid based on keywords."""
        t = text.lower()

        ir_keys = [
            "failed login", "bruteforce", "connection attempt", "nc -e",
            "/tmp/", "reverse shell", "outbound traffic", "unauthorized"
        ]

        ti_keys = [
            "apt", "malware", "ttp", "campaign", "mitre", "threat actor",
            "phishing", "malicious document", "c2"
        ]

        if any(k in t for k in ir_keys):
            return "IR"
        if any(k in t for k in ti_keys):
            return "Threat Intel"
        return "Hybrid"

    # ==========================================================================
    # Prompt loading
    # ==========================================================================
    def load_prompt_template(self, mode):
        """
        Load prompt template from /prompts.
        Does not override your prompts — keeps exact content.
        """

        safe_name = mode.lower().replace(" ", "_")
        fname = f"prompts/prompt_{safe_name}.txt"

        if os.path.exists(fname):
            with open(fname, "r", encoding="utf-8") as f:
                return f.read().strip()

        # Fallback
        return (
            "You are a cybersecurity analyst. "
            "Return ONLY a valid JSON object following the required schema."
        )

    # ==========================================================================
    # JSON extraction
    # ==========================================================================
    def extract_json(self, text):
        """Extract JSON from model output using a robust regex."""
        match = re.search(r"\{.*\}", text, re.DOTALL)
        if not match:
            return None

        try:
            return json.loads(match.group().strip())
        except Exception:
            return None

    # ==========================================================================
    # Query pipeline
    # ==========================================================================
    def query(self, user_query, model_name="qwen2.5:0.5b", forced_mode=None):
        """
        Full RAG pipeline:
        1) Ensure index loaded
        2) Detect mode or use forced
        3) Retrieve relevant chunks
        4) Build final prompt (template + context + input + schema)
        5) Run LLM
        6) Return JSON or fallback
        """

        # Load or initialize vectorstore
        if self.vectorstore is None:
            self.vectorstore = Chroma(
                persist_directory=self.db_path,
                embedding_function=self.embeddings
            )

        # Determine mode
        mode = forced_mode if forced_mode else self.detect_mode(user_query)
        prompt_template = self.load_prompt_template(mode)

        # Retrieve context chunks
        retrieved_docs = self.vectorstore.similarity_search(user_query, k=5)
        retrieved_text = "\n\n".join(doc.page_content for doc in retrieved_docs)

        # Build final augmented prompt
        full_prompt = f"""
{prompt_template}

=== Retrieved Relevant Intelligence ===
{retrieved_text}

=== User Input ===
{user_query}

=== JSON Output Requirements ===
You MUST output a JSON object with this structure:

{{
  "mode": "{mode}",
  "events": [
    {{
      "description": "",
      "severity": "High | Medium | Low",
      "tags": []
    }}
  ],
  "ioc": [],
  "mitre": [],
  "summary": "",
  "severity": "High | Medium | Low"
}}

Severity Rules:
- High: reverse shell, malware creation, C2 calls, privilege escalation
- Medium: repeated failed logins, brute force, network scans
- Low: normal / benign activity

Output JSON only. Do NOT include explanations.
"""

        # Run model
        llm = Ollama(model=model_name)
        response = llm(full_prompt)

        # Try to extract JSON cleanly
        parsed = self.extract_json(response)
        if parsed is not None:
            return json.dumps(parsed, indent=2)

        # Fallback when model does not follow instructions
        return response

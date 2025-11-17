import os
import json
from langchain_community.embeddings import OllamaEmbeddings
from langchain_community.llms import Ollama
from langchain_community.vectorstores import Chroma
from langchain_text_splitters import RecursiveCharacterTextSplitter
from langchain_community.document_loaders import TextLoader

class ThreatRAG:
    def __init__(self, data_path="data/threat_reports", db_path="vectorstore"):
        self.data_path = data_path
        self.db_path = db_path
        self.embeddings = OllamaEmbeddings(model="nomic-embed-text")
        self.vectorstore = None

    def build_index(self):    
        """Load threat reports and build the vector database"""
        print("[+] Loading threat reports...")
        docs = []
        for filename in os.listdir(self.data_path):
            if filename.endswith(".txt"):
                loader = TextLoader(os.path.join(self.data_path, filename))
                docs.extend(loader.load())

        splitter = RecursiveCharacterTextSplitter(chunk_size=800, chunk_overlap=200)
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
    
    def detect_mode(self, text):
        """Detect analysis mode automatically based on input text"""
        t = text.lower()
        if any(k in t for k in ["failed login", "connection attempt", "nc -e", "outbound traffic", "/tmp/", "bruteforce"]):
            return "IR"
        elif any(k in t for k in ["apt", "malware", "ttp", "mitre", "campaign", "threat actor", "phishing"]):
            return "Threat Intel"
        else:
            return "Hybrid"

    def load_prompt_template(self, mode):
        """Load prompt text from /prompts directory"""
        fname = f"prompts/prompt_{mode.lower().replace(' ', '_')}.txt"
        if os.path.exists(fname):
            with open(fname, "r", encoding="utf-8") as f:
                return f.read()
        return "You are a cybersecurity analyst. Return valid JSON."

    def query(self, user_query, model_name="qwen2.5:0.5b", forced_mode=None):
        """Query the knowledge base using a chosen Ollama model"""

        if self.vectorstore is None:
            self.vectorstore = Chroma(
                persist_directory=self.db_path,
                embedding_function=self.embeddings
            )

        mode = forced_mode if forced_mode else self.detect_mode(user_query)
        prompt_template = self.load_prompt_template(mode)

        # === Fine-tuned prompt with severity logic ===
        full_prompt = f"""
{prompt_template}

Analyze the following input and:
- For each event, classify severity as High / Medium / Low.
- Mark reverse shells, malware creation, outbound C2, or privilege escalation as High.
- Mark failed logins or scans as Medium.
- Mark normal connections as Low.
- Add a global "severity" field summarizing the overall threat level (highest severity seen).
- Fill a "summary" field describing the main risk.

Input data:
{user_query}
"""

        llm = Ollama(model=model_name)
        response = llm(full_prompt)

        # Try to extract JSON only
        try:
            start = response.find("{")
            end = response.rfind("}") + 1
            parsed = json.loads(response[start:end])
            return json.dumps(parsed, indent=2)
        except Exception:
            return response

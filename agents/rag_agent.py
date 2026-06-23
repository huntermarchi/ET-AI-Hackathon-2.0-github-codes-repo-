"""
KernelSentinel — ATT&CK RAG Threat Intelligence Agent
RAG over MITRE ATT&CK STIX v14 + CERT-In advisories.
LLM: Claude Sonnet 4.6
"""
import json, argparse, anthropic
from pathlib import Path

SYSTEM = """You are a CERT-In threat intelligence analyst.
Given an anomaly alert and retrieved ATT&CK context, respond with:
1. TTP Match (ID + name + confidence %)
2. Threat Explanation (plain language, 3-4 sentences)
3. Predicted Next Move (attacker's likely next step)
4. Immediate Containment Actions (numbered list, max 4)
Be concise. Cite ATT&CK IDs. Assume Indian government infrastructure context."""

class ATTACKRAGAgent:
    def __init__(self, corpus_path: str = "./corpus"):
        self.client = anthropic.Anthropic()
        self.corpus_path = Path(corpus_path)
        self._index = None

    def _build_index(self):
        try:
            from llama_index.core import VectorStoreIndex, SimpleDirectoryReader
            docs = SimpleDirectoryReader(str(self.corpus_path)).load_data()
            self._index = VectorStoreIndex.from_documents(docs)
            print(f"[rag_agent] indexed {len(docs)} documents")
        except Exception as e:
            print(f"[rag_agent] index build failed: {e} — using fallback context")

    def _retrieve(self, query: str) -> str:
        if self._index is None:
            return "[ATT&CK corpus not indexed — using model knowledge]"
        retriever = self._index.as_retriever(similarity_top_k=5)
        nodes = retriever.retrieve(query)
        return "\n\n".join(n.text for n in nodes)

    def analyse(self, alert: dict) -> dict:
        query   = f"syscall {alert['syscall']} sigma {alert['sigma']} {alert['ttp_hint']}"
        context = self._retrieve(query)
        prompt  = (
            f"Alert: {json.dumps(alert, indent=2)}\n\n"
            f"Retrieved ATT&CK context:\n{context}"
        )
        response = self.client.messages.create(
            model      = "claude-sonnet-4-6",
            max_tokens = 1000,
            system     = SYSTEM,
            messages   = [{"role": "user", "content": prompt}],
        )
        return {
            "alert_id": alert["alert_id"],
            "severity": alert["severity"],
            "ttp":      alert["ttp_hint"],
            "analysis": response.content[0].text,
        }

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--ingest", type=str, help="Path to corpus directory to index")
    parser.add_argument("--alert", type=str, help="JSON alert string to analyse")
    args = parser.parse_args()

    agent = ATTACKRAGAgent(corpus_path=args.ingest or "./corpus")
    if args.ingest:
        agent._build_index()
    if args.alert:
        result = agent.analyse(json.loads(args.alert))
        print(json.dumps(result, indent=2))

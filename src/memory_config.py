# src/memory_config.py
from chromadb.utils.embedding_functions import SentenceTransformerEmbeddingFunction
from crewai.memory import EntityMemory, ShortTermMemory, LongTermMemory
from crewai.memory.storage.rag_storage import RAGStorage
from crewai.memory.storage.ltm_sqlite_storage import LTMSQLiteStorage

# ================================
# EMBEDDINGS GRATUITS (HuggingFace)
# ================================
# memory_config.py - VERSION OLLAMA
# pip install ollama chromadb crewai

import ollama
import chromadb
from crewai.memory import EntityMemory, ShortTermMemory, LongTermMemory
from crewai.memory.storage.rag_storage import RAGStorage
from crewai.memory.storage.ltm_sqlite_storage import LTMSQLiteStorage

# ================================
# EMBEDDINGS OLLAMA (100% LOCAL)
# Modèle recommandé : nomic-embed-text
# ollama pull nomic-embed-text
# ================================

short_term_memory = ShortTermMemory(
    storage=RAGStorage(
        type="short_term",
        embedder_config={
            "provider": "ollama",
            "config": {
                "model": "nomic-embed-text",  # spécialisé embeddings
                "base_url": "http://localhost:11434"
            }
        }
    )
)

long_term_memory = LongTermMemory(
    storage=LTMSQLiteStorage(
        db_path="memory/long_term_memory.db"
    )
)

entity_memory = EntityMemory(
    storage=RAGStorage(
        type="entities",
        embedder_config={
            "provider": "ollama",
            "config": {
                "model": "nomic-embed-text",
                "base_url": "http://localhost:11434"
            }
        }
    )
)

# ================================
# MEMOIRE LONG TERME
# stocke les expériences passées dans SQLite
# ================================
long_term_memory = LongTermMemory(
    storage=LTMSQLiteStorage(
        db_path="memory/long_term_memory.db"
    )
)

# ================================
# MEMOIRE ENTITES
# stocke les informations sur les entités
# (serveurs, IPs, services...)
# ================================
entity_memory = EntityMemory(
    storage=RAGStorage(
        type="entities",
        embedder_config={
            "provider": "huggingface",
            "config": {
                "model": "sentence-transformers/all-MiniLM-L6-v2"
            }
        }
    )
)
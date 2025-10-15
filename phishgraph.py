import numpy as np
import pandas as pd
from sentence_transformers import SentenceTransformer
import diskannpy
import os
import requests
from tqdm import tqdm
import warnings
import shutil

# Suppress a specific FutureWarning from sentence_transformers
warnings.filterwarnings("ignore", category=FutureWarning, module='sentence_transformers.SentenceTransformer')


class PhishGraphSearch:
    """
    A class to demonstrate the core query logic of the PhishGraph system.
    """
    def __init__(self, data_path='data_urls'):
        self.data_path = data_path
        self.model = SentenceTransformer('all-MiniLM-L6-v2')
        self.index = None
        self.vectors = None
        self.metadata = None
        
        #os.makedirs(self.data_path, exist_ok=True)
        #print("PhishGraphSearch initialized.")
        #print("-" * 30)

    def _download_and_load_data(self):
        """Downloads the Malicious URLs dataset from Kaggle via a direct link."""
        csv_path = 'malicious_urls.csv'
               
        print("Loading and preprocessing dataset...")
        df = pd.read_csv(csv_path)
        # For demonstration, we'll use a smaller subset. Remove .head() for the full dataset.
        df = df.head(500)

        print(df) 
        # Create a mapping for the categorical 'type' attribute
        df['type_id'] = df['type'].astype('category').cat.codes
        self.metadata = df[['url', 'type', 'type_id']].to_dict('records')
        print(f"Loaded {len(self.metadata)} URLs.")
        return df

    def _generate_embeddings(self, urls):
        """Generates vector embeddings for a list of URLs."""
        print("Loading Sentence-BERT model ('all-MiniLM-L6-v2')...")
        #self.model = SentenceTransformer('all-MiniLM-L6-v2')
        
        print("Generating URL embeddings...")
        embeddings = self.model.encode(urls, show_progress_bar=True, normalize_embeddings=True)
        return embeddings.astype(np.float32)

    def build_index(self):
        """
        Prepares data, generates embeddings, and builds a DiskANN index.
        This simulates the ingestion pipeline. [cite: 631]
        """
        df = self._download_and_load_data()
        if df is None:
            return

        os.makedirs(self.data_path, exist_ok=True)
        vectors_path = os.path.join(self.data_path, 'vectors.npy')
        
        if os.path.exists(vectors_path):
            print("Loading existing vectors from disk...")
            self.vectors = np.load(vectors_path)
            print(self.vectors)
        else:
            self.vectors = self._generate_embeddings(df['url'].tolist())
            np.save(vectors_path, self.vectors)

        print(f"Generated {self.vectors.shape[0]} vectors of dimension {self.vectors.shape[1]}.")
        
        index_path = os.path.join(self.data_path,  'phishgraph_index')
        if os.path.exists(index_path):
             shutil.rmtree(index_path)
        os.makedirs(index_path, exist_ok=True)        

        
        
        print("Building DiskANN index...")
        # Build the Vamana graph index [cite: 597]
        diskannpy.build_disk_index(
                data=self.vectors,
                distance_metric="l2",  # For normalized vectors, l2 is proportional to cosine similarity
                index_directory=index_path,
                #index_prefix="phishgraph_index",
                complexity=64,
                graph_degree=32,
                num_threads=8,
                search_memory_maximum=0.00003,
                build_memory_maximum=1
        )

        print("Index built successfully.")

        print("Loading DiskANN index for querying...")
        
        #if not os.path.exists(index_path):
        #   print("Building DiskANN index...")

        self.index = diskannpy.StaticDiskIndex(
             index_directory=index_path,
             #index_prefix="phishgraph_index",
             #initial_search_complexity=100, # L_search at insertion time
             vector_dtype=np.float32,
             num_threads=8,
             num_nodes_to_cache=10_000  
        )

    def search(self, query_url, query_type_id, k=10, L=100, w_a=0.5):
        """
        Performs a hybrid search using the PhishGraph methodology.
        This function implements the three-phase query pipeline. [cite: 741]
        
        Args:
            query_url (str): The URL to search for.
            query_type_id (int): The integer ID for the desired URL type.
            k (int): The final number of results to return.
            L (int): The size of the candidate set from the initial vector search.
            w_a (float): The attribute weight for the Hybrid Fusion Distance. [cite: 532]
        
        Returns:
            list: A list of tuples, each containing (URL, type, hybrid_distance).
        """
        #if self.index is None or self.model is None:
        #    print("Index not built. Please run .build_index() first.")
        #    return []

        # Phase 1 & 2 (simplified): Embed query and perform beam search on the graph
        print(f"\nSearching for URLs similar to '{query_url}' with type_id={query_type_id}")
        print(f"Parameters: k={k}, L={L}, w_a={w_a}")
        
        query_vector = self.model.encode([query_url], normalize_embeddings=True).astype(np.float32)
        
        # Get a large candidate pool of L neighbors using pure vector search
        indices, l2_distances = self.index.batch_search(query_vector, k_neighbors=10, num_threads=16, complexity=5, beam_width=2 )
        indices, l2_distances = indices[0], l2_distances[0]

        # Phase 3: High-Fidelity Re-ranking using Hybrid Fusion Distance [cite: 703]
        candidates = []
        query_attrs = {'type_id': query_type_id}

        for i in range(len(indices)):
            doc_id = indices[i]
            doc_vector = self.vectors[doc_id]
            doc_attrs = self.metadata[doc_id]
            
            # 1. Semantic Distance (s)
            # For normalized vectors, (1 - dot_product) is cosine distance.
            # L2 distance is also a valid proxy. Let's use it as the paper's s(u,v).
            semantic_distance = l2_distances[i]

            # 2. Attribute Penalty (chi) 
            # Here, we use Hamming distance on the 'type_id' attribute
            attribute_penalty = 0 if query_attrs['type_id'] == doc_attrs['type_id'] else 1
            
            # 3. Hybrid Fusion Distance (Gamma)
            hybrid_distance = semantic_distance + w_a * attribute_penalty
            
            candidates.append({
                'id': doc_id,
                'url': doc_attrs['url'],
                'type': doc_attrs['type'],
                'semantic_dist': semantic_distance,
                'attribute_penalty': attribute_penalty,
                'hybrid_dist': hybrid_distance
            })

        # Re-rank the candidates based on the hybrid score
        ranked_results = sorted(candidates, key=lambda x: x['hybrid_dist'])
        
        # Filter out candidates that don't match if w_a is very high (acting as hard filter)
        # And return the top-k results
        final_results = []
        for res in ranked_results:
            # Optional: for very high w_a, you might only want matching attributes
            # if w_a > 10 and res['attribute_penalty'] != 0:
            #     continue
            final_results.append((res['url'], res['type'], res['hybrid_dist']))
            if len(final_results) == k:
                break
                
        return final_results

# --- Main Execution ---
if __name__ == "__main__":
    pg_search = PhishGraphSearch(data_path='./phishgraph_data')
    
    # This will download data, create embeddings, and build the index on the first run.
    # Subsequent runs will load the saved files.
    pg_search.build_index()

    # --- Example Query ---
    # We will simulate the example from Table 1 in the paper. [cite: 629]
    # Let's find a phishing URL and a malware URL that are semantically close.
    # Query: A phishing URL. Goal: Find other phishing URLs.
    
    query_url_example = "http://www.pcbanking-groups-verify-updated-information-servipag.loqo.com/"
    query_type_id_example = 2 # 'phishing' has id 2 in this dataset

    # Scenario 1: Low w_a (prioritizes semantics) [cite: 536, 589]
    # A semantically similar 'malware' URL might be ranked higher than a less similar 'phishing' one.
    print("-" * 30)
    results_low_wa = pg_search.search(
        query_url=query_url_example, 
        query_type_id=query_type_id_example,
        w_a=0.05
    )
    print("\n--- Results with LOW Attribute Weight (w_a = 0.05) ---")
    for url, url_type, score in results_low_wa:
        print(f"Type: {url_type:<12} | Score: {score:.4f} | URL: {url}")
        
    # Scenario 2: High w_a (prioritizes attributes) [cite: 539, 591]
    # The attribute penalty will push any non-'phishing' results down the list,
    # ensuring the top results match the desired type.
    print("-" * 30)
    results_high_wa = pg_search.search(
        query_url=query_url_example, 
        query_type_id=query_type_id_example,
        w_a=0.8
    )
    print("\n--- Results with HIGH Attribute Weight (w_a = 0.8) ---")
    for url, url_type, score in results_high_wa:
        print(f"Type: {url_type:<12} | Score: {score:.4f} | URL: {url}")

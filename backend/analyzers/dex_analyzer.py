import os
import re
from typing import Dict, Any, List, Tuple

class DexAnalyzer:
    """
    Extracts printable ASCII / UTF-8 strings from .dex bytecode files and XML/resource files
    and searches for patterns, classes, methods, and line context.
    """
    @staticmethod
    def extract_strings(extracted_dir: str) -> List[Tuple[str, str, int]]:
        """
        Returns a list of tuples: (relative_file_path, line_content, line_number)
        """
        results = []
        for root, _, files in os.walk(extracted_dir):
            for file in files:
                full_path = os.path.join(root, file)
                rel_path = os.path.relpath(full_path, extracted_dir)
                
                # Check dex files, xml files, json, properties, txt, etc.
                if file.endswith(('.dex', '.xml', '.json', '.properties', '.txt', '.java', '.smali')):
                    try:
                        with open(full_path, 'rb') as f:
                            content = f.read()
                        
                        # Extract ASCII printable sequences of length >= 4
                        printable_strings = re.findall(rb'[\x20-\x7E]{4,}', content)
                        for idx, s_bytes in enumerate(printable_strings):
                            try:
                                s = s_bytes.decode('utf-8', errors='ignore')
                                results.append((rel_path, s, idx + 1))
                            except Exception:
                                pass
                    except Exception:
                        pass
        return results

# dependency_tree_builder.py

import subprocess
import json
from typing import Dict, List

class DependencyTreeBuilder:
    """Build complete dependency tree including transitive deps"""
    
    @staticmethod
    def build_npm_tree(package_dir: str) -> Dict:
        """
        Get complete dependency tree for npm project
        Uses 'npm ls --json' for accuracy
        """
        try:
            result = subprocess.run(
                ['npm', 'ls', '--json'],
                cwd=package_dir,
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if result.returncode != 0:
                print(f"Warning: npm ls returned non-zero: {result.stderr}")
            
            tree = json.loads(result.stdout)
            return tree
            
        except subprocess.TimeoutExpired:
            print(f"Timeout: npm ls took too long")
            return {}
        except json.JSONDecodeError:
            print(f"Failed to parse npm output as JSON")
            return {}
    
    @staticmethod
    def build_python_tree(requirements_file: str) -> Dict:
        """
        Get dependency tree for Python project
        Uses 'pip-audit' or 'pipdeptree'
        """
        try:
            result = subprocess.run(
                ['pip', 'install', 'pipdeptree'],
                capture_output=True,
                timeout=60
            )
            
            result = subprocess.run(
                ['pipdeptree', '--json'],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            tree = json.loads(result.stdout)
            return tree
            
        except Exception as e:
            print(f"Failed to build Python tree: {e}")
            return {}
    
    @staticmethod
    def build_maven_tree(pom_file: str) -> Dict:
        """
        Get dependency tree for Maven project
        Uses 'mvn dependency:tree'
        """
        try:
            result = subprocess.run(
                ['mvn', 'dependency:tree', '-DoutputFile=/tmp/tree.txt'],
                cwd=pom_file.parent,
                capture_output=True,
                timeout=120
            )
            
            # Parse the text output
            with open('/tmp/tree.txt') as f:
                return f.read()
                
        except Exception as e:
            print(f"Failed to build Maven tree: {e}")
            return {}

# Example output structure:
"""
{
  "name": "my-app",
  "version": "1.0.0",
  "dependencies": {
    "express": {
      "version": "4.18.2",
      "dependencies": {
        "body-parser": {
          "version": "1.20.0",
          "dependencies": {
            "bytes": {
              "version": "3.1.0"
            }
          }
        }
      }
    },
    "lodash": {
      "version": "4.17.21"
    }
  }
}
"""
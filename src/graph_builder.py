# graph_builder.py

"""
Graph Builder Module

Builds interactive attack graph data structures for D3.js visualization.
Generates nodes, edges, and metadata for the attack path visualization.
"""

from typing import Dict, List, Optional, Set, Tuple
from dataclasses import dataclass, field
from datetime import datetime
import json
import uuid


@dataclass
class GraphNode:
    """Represents a node in the attack graph."""
    id: str
    label: str
    node_type: str  # "root", "dependency", "vulnerability", "impact", "exploit"
    severity: Optional[str] = None  # "critical", "high", "medium", "low"
    version: Optional[str] = None
    cve_id: Optional[str] = None
    is_transitive: bool = False
    is_compromised: bool = False
    x: Optional[float] = None
    y: Optional[float] = None
    metadata: Dict = field(default_factory=dict)


@dataclass
class GraphEdge:
    """Represents an edge in the attack graph."""
    id: str
    source: str
    target: str
    edge_type: str  # "depends_on", "exploits", "leads_to", "compromises"
    label: Optional[str] = None
    animated: bool = False
    metadata: Dict = field(default_factory=dict)


@dataclass
class AttackGraph:
    """Complete attack graph data structure."""
    nodes: List[GraphNode] = field(default_factory=list)
    edges: List[GraphEdge] = field(default_factory=list)
    metadata: Dict = field(default_factory=dict)
    
    def to_dict(self) -> Dict:
        """Convert to dictionary for JSON serialization."""
        return {
            'nodes': [
                {
                    'id': n.id,
                    'label': n.label,
                    'type': n.node_type,
                    'severity': n.severity,
                    'version': n.version,
                    'cve_id': n.cve_id,
                    'is_transitive': n.is_transitive,
                    'is_compromised': n.is_compromised,
                    'metadata': n.metadata
                }
                for n in self.nodes
            ],
            'edges': [
                {
                    'id': e.id,
                    'source': e.source,
                    'target': e.target,
                    'type': e.edge_type,
                    'label': e.label,
                    'animated': e.animated,
                    'metadata': e.metadata
                }
                for e in self.edges
            ],
            'metadata': self.metadata
        }
    
    def to_json(self) -> str:
        """Convert to JSON string."""
        return json.dumps(self.to_dict(), indent=2)


class GraphBuilder:
    """
    Builds attack graphs for visualization with D3.js.
    
    Creates hierarchical graphs showing:
    - Application root
    - Direct dependencies
    - Transitive dependencies
    - Vulnerability nodes
    - Impact nodes
    - Attack paths
    """
    
    # Node colors by type and severity
    NODE_COLORS = {
        'root': '#4a90d9',
        'dependency': {
            'direct': '#50c878',
            'transitive': '#9b59b6'
        },
        'vulnerability': {
            'critical': '#e74c3c',
            'high': '#e67e22',
            'medium': '#f1c40f',
            'low': '#2ecc71'
        },
        'impact': '#9b59b6',
        'exploit': '#e74c3c'
    }
    
    # Edge colors by type
    EDGE_COLORS = {
        'depends_on': '#7f8c8d',
        'exploits': '#e74c3c',
        'leads_to': '#e67e22',
        'compromises': '#9b59b6'
    }
    
    def __init__(self, project_name: str = "Application"):
        """
        Initialize the graph builder.
        
        Args:
            project_name: Name of the project being analyzed
        """
        self.project_name = project_name
        self.graph = AttackGraph()
        self.node_map: Dict[str, GraphNode] = {}
        self._node_counter = 0
    
    def build_graph(
        self,
        dependencies: List[Dict],
        findings: List[Dict],
        attack_paths: Optional[List[Dict]] = None
    ) -> AttackGraph:
        """
        Build complete attack graph from dependencies and findings.
        
        Args:
            dependencies: List of dependency objects
            findings: List of vulnerability findings
            attack_paths: Optional list of attack path data
            
        Returns:
            AttackGraph object
        """
        self.graph = AttackGraph()
        self.node_map = {}
        
        # Add root node (application)
        self._add_root_node()
        
        # Add dependency nodes
        self._add_dependency_nodes(dependencies, findings)
        
        # Add vulnerability nodes
        self._add_vulnerability_nodes(findings)
        
        # Add impact nodes
        self._add_impact_nodes(findings)
        
        # Add edges
        self._add_dependency_edges(dependencies, findings)
        self._add_vulnerability_edges(findings)
        self._add_impact_edges(findings)
        
        # Add attack path edges if provided
        if attack_paths:
            self._add_attack_path_edges(attack_paths)
        
        # Add metadata
        self._add_metadata(dependencies, findings)
        
        return self.graph
    
    def _add_root_node(self) -> None:
        """Add the application root node."""
        root_id = 'root-app'
        node = GraphNode(
            id=root_id,
            label=self.project_name,
            node_type='root',
            severity=None,
            metadata={
                'color': self.NODE_COLORS['root'],
                'icon': '📦',
                'description': 'Application root'
            }
        )
        self.graph.nodes.append(node)
        self.node_map[root_id] = node
    
    def _add_dependency_nodes(
        self,
        dependencies: List[Dict],
        findings: List[Dict]
    ) -> None:
        """Add dependency nodes to the graph."""
        # Get packages with vulnerabilities
        vuln_packages = {f.get('package', '').lower() for f in findings}
        
        # Track unique packages
        seen_packages: Set[str] = set()
        
        for dep in dependencies:
            name = dep.get('name', '')
            if not name or name.lower() in seen_packages:
                continue
            
            seen_packages.add(name.lower())
            
            is_transitive = dep.get('transitive', False)
            has_vulnerability = name.lower() in vuln_packages
            
            node_id = f"dep-{name}"
            
            # Determine node type
            if has_vulnerability:
                # Find the severity
                severity = next(
                    (f.get('severity') for f in findings 
                     if f.get('package', '').lower() == name.lower()),
                    'medium'
                )
                node_type = 'vulnerability'
            else:
                node_type = 'dependency'
                severity = None
            
            node = GraphNode(
                id=node_id,
                label=name,
                node_type=node_type,
                severity=severity,
                version=dep.get('version'),
                is_transitive=is_transitive,
                is_compromised=has_vulnerability,
                metadata={
                    'color': self._get_node_color(node_type, severity, is_transitive),
                    'icon': '📦' if not has_vulnerability else '⚠️',
                    'description': f"{'Transitive' if is_transitive else 'Direct'} dependency",
                    'ecosystem': dep.get('ecosystem', 'npm')
                }
            )
            
            self.graph.nodes.append(node)
            self.node_map[node_id] = node
    
    def _add_vulnerability_nodes(self, findings: List[Dict]) -> None:
        """Add vulnerability nodes to the graph."""
        for finding in findings:
            pkg_name = finding.get('package', '')
            cve_id = finding.get('cve', '')
            severity = finding.get('severity', 'medium')
            
            if not cve_id:
                continue
            
            node_id = f"vuln-{cve_id}"
            
            node = GraphNode(
                id=node_id,
                label=cve_id,
                node_type='vulnerability',
                severity=severity,
                version=finding.get('version'),
                cve_id=cve_id,
                is_compromised=True,
                metadata={
                    'color': self._get_node_color('vulnerability', severity, False),
                    'icon': '🔴',
                    'description': finding.get('description', '')[:100],
                    'exploit_type': finding.get('exploit_type', 'Unknown'),
                    'has_patch': finding.get('has_patch', False),
                    'fixed_version': finding.get('fixed_version')
                }
            )
            
            self.graph.nodes.append(node)
            self.node_map[node_id] = node
    
    def _add_impact_nodes(self, findings: List[Dict]) -> None:
        """Add impact nodes showing potential consequences."""
        # Common impact types
        impact_types = [
            'Remote Code Execution',
            'Data Breach',
            'Credential Theft',
            'Privilege Escalation',
            'Service Disruption',
            'Internal Network Access',
            'Session Hijacking',
            'Supply Chain Compromise'
        ]
        
        # Track added impacts
        added_impacts: Set[str] = set()
        
        for finding in findings:
            cve_id = finding.get('cve', '')
            severity = finding.get('severity', 'medium')
            
            # Select impacts based on severity
            if severity == 'critical':
                impacts = ['Remote Code Execution', 'Data Breach', 'Supply Chain Compromise']
            elif severity == 'high':
                impacts = ['Credential Theft', 'Privilege Escalation', 'Internal Network Access']
            else:
                impacts = ['Session Hijacking', 'Service Disruption']
            
            for impact in impacts:
                if impact in added_impacts:
                    continue
                
                added_impacts.add(impact)
                
                node_id = f"impact-{impact.lower().replace(' ', '-')}"
                
                node = GraphNode(
                    id=node_id,
                    label=impact,
                    node_type='impact',
                    severity=severity,
                    metadata={
                        'color': self.NODE_COLORS['impact'],
                        'icon': '💥',
                        'description': f'Potential impact: {impact}',
                        'related_cve': cve_id
                    }
                )
                
                self.graph.nodes.append(node)
                self.node_map[node_id] = node
    
    def _add_dependency_edges(
        self,
        dependencies: List[Dict],
        findings: List[Dict]
    ) -> None:
        """Add edges from root to dependencies."""
        vuln_packages = {f.get('package', '').lower() for f in findings}
        
        for dep in dependencies:
            name = dep.get('name', '')
            if not name:
                continue
            
            # Only add edge for first occurrence
            if dep.get('is_first', True):
                edge_id = f"edge-root-{name}"
                
                edge = GraphEdge(
                    id=edge_id,
                    source='root-app',
                    target=f"dep-{name}",
                    edge_type='depends_on',
                    label='depends on',
                    animated=dep.get('package', '').lower() in vuln_packages,
                    metadata={
                        'color': self.EDGE_COLORS['depends_on'],
                        'style': 'solid'
                    }
                )
                
                self.graph.edges.append(edge)
    
    def _add_vulnerability_edges(self, findings: List[Dict]) -> None:
        """Add edges from dependencies to vulnerabilities."""
        for finding in findings:
            pkg_name = finding.get('package', '')
            cve_id = finding.get('cve', '')
            
            if not cve_id or not pkg_name:
                continue
            
            dep_node_id = f"dep-{pkg_name}"
            vuln_node_id = f"vuln-{cve_id}"
            
            # Check if nodes exist
            if dep_node_id not in self.node_map:
                continue
            
            edge_id = f"edge-{pkg_name}-{cve_id}"
            
            edge = GraphEdge(
                id=edge_id,
                source=dep_node_id,
                target=vuln_node_id,
                edge_type='exploits',
                label='vulnerable to',
                animated=True,
                metadata={
                    'color': self.EDGE_COLORS['exploits'],
                    'style': 'dashed',
                    'severity': finding.get('severity', 'medium')
                }
            )
            
            self.graph.edges.append(edge)
    
    def _add_impact_edges(self, findings: List[Dict]) -> None:
        """Add edges from vulnerabilities to impacts."""
        for finding in findings:
            cve_id = finding.get('cve', '')
            severity = finding.get('severity', 'medium')
            
            if not cve_id:
                continue
            
            vuln_node_id = f"vuln-{cve_id}"
            
            # Select impacts based on severity
            if severity == 'critical':
                impacts = ['Remote Code Execution', 'Data Breach', 'Supply Chain Compromise']
            elif severity == 'high':
                impacts = ['Credential Theft', 'Privilege Escalation']
            else:
                impacts = ['Session Hijacking']
            
            for impact in impacts:
                impact_node_id = f"impact-{impact.lower().replace(' ', '-')}"
                
                if impact_node_id not in self.node_map:
                    continue
                
                edge_id = f"edge-{cve_id}-{impact.lower().replace(' ', '-')}"
                
                edge = GraphEdge(
                    id=edge_id,
                    source=vuln_node_id,
                    target=impact_node_id,
                    edge_type='leads_to',
                    label='can lead to',
                    animated=True,
                    metadata={
                        'color': self.EDGE_COLORS['leads_to'],
                        'style': 'dotted'
                    }
                )
                
                self.graph.edges.append(edge)
    
    def _add_attack_path_edges(self, attack_paths: List[Dict]) -> None:
        """Add edges representing complete attack paths."""
        for path in attack_paths:
            path_id = path.get('path_id', '')
            chain = path.get('chain', [])
            
            for i in range(len(chain) - 1):
                step = chain[i]
                next_step = chain[i + 1]
                
                # Create edge between steps
                edge_id = f"path-{path_id}-step-{i}"
                
                edge = GraphEdge(
                    id=edge_id,
                    source=step.get('id', f"step-{i}"),
                    target=next_step.get('id', f"step-{i+1}"),
                    edge_type='compromises',
                    label='attack progression',
                    animated=True,
                    metadata={
                        'color': '#e74c3c',
                        'style': 'animated',
                        'path_id': path_id
                    }
                )
                
                self.graph.edges.append(edge)
    
    def _add_metadata(
        self,
        dependencies: List[Dict],
        findings: List[Dict]
    ) -> None:
        """Add metadata to the graph."""
        self.graph.metadata = {
            'generated_at': datetime.now().isoformat(),
            'project_name': self.project_name,
            'statistics': {
                'total_nodes': len(self.graph.nodes),
                'total_edges': len(self.graph.edges),
                'total_dependencies': len(dependencies),
                'vulnerabilities': {
                    'critical': sum(1 for f in findings if f.get('severity') == 'critical'),
                    'high': sum(1 for f in findings if f.get('severity') == 'high'),
                    'medium': sum(1 for f in findings if f.get('severity') == 'medium'),
                    'low': sum(1 for f in findings if f.get('severity') == 'low'),
                }
            },
            'visualization': {
                'layout': 'force-directed',
                'physics': {
                    'enabled': True,
                    'stabilization_iterations': 100
                }
            }
        }
    
    def _get_node_color(
        self,
        node_type: str,
        severity: Optional[str] = None,
        is_transitive: bool = False
    ) -> str:
        """Get the color for a node based on its type and severity."""
        if node_type == 'root':
            return self.NODE_COLORS['root']
        elif node_type == 'dependency':
            if is_transitive:
                return self.NODE_COLORS['dependency']['transitive']
            return self.NODE_COLORS['dependency']['direct']
        elif node_type == 'vulnerability' and severity:
            return self.NODE_COLORS['vulnerability'].get(severity, '#95a5a6')
        elif node_type == 'impact':
            return self.NODE_COLORS['impact']
        
        return '#95a5a6'
    
    def get_filtered_graph(
        self,
        severity_filter: Optional[List[str]] = None,
        show_only_exploitable: bool = False,
        show_only_transitive: bool = False
    ) -> AttackGraph:
        """
        Get a filtered version of the graph.
        
        Args:
            severity_filter: List of severities to include
            show_only_exploitable: Only show vulnerable packages
            show_only_transitive: Only show transitive dependencies
            
        Returns:
            Filtered AttackGraph
        """
        filtered = AttackGraph()
        filtered.metadata = self.graph.metadata.copy()
        
        # Filter nodes
        for node in self.graph.nodes:
            include = True
            
            if severity_filter and node.severity not in severity_filter:
                include = False
            
            if show_only_exploitable and node.node_type != 'vulnerability':
                include = False
            
            if show_only_transitive and not node.is_transitive:
                include = False
            
            if include:
                filtered.nodes.append(node)
        
        # Filter edges (only include edges between filtered nodes)
        node_ids = {n.id for n in filtered.nodes}
        for edge in self.graph.edges:
            if edge.source in node_ids and edge.target in node_ids:
                filtered.edges.append(edge)
        
        return filtered
    
    def get_attack_chain_graph(
        self,
        cve_id: str,
        max_depth: int = 5
    ) -> AttackGraph:
        """
        Get a focused graph showing only the attack chain for a specific CVE.
        
        Args:
            cve_id: The CVE ID to focus on
            max_depth: Maximum depth to traverse
            
        Returns:
            AttackGraph showing the attack chain
        """
        chain_graph = AttackGraph()
        
        # Find the vulnerability node
        vuln_node = self.node_map.get(f"vuln-{cve_id}")
        if not vuln_node:
            return chain_graph
        
        # Add the vulnerability node
        chain_graph.nodes.append(vuln_node)
        
        # Find connected edges and nodes
        visited: Set[str] = {vuln_node.id}
        to_visit = [vuln_node.id]
        
        depth = 0
        while to_visit and depth < max_depth:
            current_id = to_visit.pop(0)
            
            for edge in self.graph.edges:
                if edge.source == current_id and edge.target not in visited:
                    target_node = self.node_map.get(edge.target)
                    if target_node:
                        chain_graph.nodes.append(target_node)
                        chain_graph.edges.append(edge)
                        visited.add(edge.target)
                        to_visit.append(edge.target)
                
                elif edge.target == current_id and edge.source not in visited:
                    source_node = self.node_map.get(edge.source)
                    if source_node:
                        chain_graph.nodes.append(source_node)
                        chain_graph.edges.append(edge)
                        visited.add(edge.source)
                        to_visit.append(edge.source)
            
            depth += 1
        
        return chain_graph
    
    def export_for_d3(self) -> str:
        """
        Export graph data in D3.js-compatible format.
        
        Returns:
            JSON string suitable for D3.js force graph
        """
        d3_data = {
            'nodes': [
                {
                    'id': n.id,
                    'name': n.label,
                    'group': n.node_type,
                    'severity': n.severity,
                    'val': 30 if n.node_type == 'root' else 20 if n.node_type == 'vulnerability' else 10,
                    'color': n.metadata.get('color', '#95a5a6'),
                    'icon': n.metadata.get('icon', ''),
                    'info': n.metadata
                }
                for n in self.graph.nodes
            ],
            'links': [
                {
                    'source': e.source,
                    'target': e.target,
                    'type': e.edge_type,
                    'label': e.label,
                    'animated': e.animated,
                    'color': e.metadata.get('color', '#95a5a6')
                }
                for e in self.graph.edges
            ],
            'metadata': self.graph.metadata
        }
        
        return json.dumps(d3_data, indent=2)
    
    def get_statistics(self) -> Dict:
        """Get graph statistics."""
        return {
            'total_nodes': len(self.graph.nodes),
            'total_edges': len(self.graph.edges),
            'node_types': self._count_by_type(self.graph.nodes),
            'severity_distribution': self._count_by_severity(self.graph.nodes),
            'edge_types': self._count_by_type_edges(self.graph.edges)
        }
    
    def _count_by_type(self, nodes: List[GraphNode]) -> Dict[str, int]:
        """Count nodes by type."""
        counts: Dict[str, int] = {}
        for node in nodes:
            counts[node.node_type] = counts.get(node.node_type, 0) + 1
        return counts
    
    def _count_by_severity(self, nodes: List[GraphNode]) -> Dict[str, int]:
        """Count nodes by severity."""
        counts: Dict[str, int] = {}
        for node in nodes:
            if node.severity:
                counts[node.severity] = counts.get(node.severity, 0) + 1
        return counts
    
    def _count_by_type_edges(self, edges: List[GraphEdge]) -> Dict[str, int]:
        """Count edges by type."""
        counts: Dict[str, int] = {}
        for edge in edges:
            counts[edge.edge_type] = counts.get(edge.edge_type, 0) + 1
        return counts
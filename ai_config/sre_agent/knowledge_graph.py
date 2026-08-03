import json
from asgiref.sync import sync_to_async
from chatbot.models import InfrastructureNode, InfrastructureEdge

class KnowledgeGraph:
    """Manages the Infrastructure Knowledge Graph."""
    
    @classmethod
    async def add_node(cls, name: str, node_type: str, properties: dict = None):
        if properties is None:
            properties = {}
        node, created = await sync_to_async(InfrastructureNode.objects.get_or_create)(
            name=name, node_type=node_type,
            defaults={'properties': properties}
        )
        if not created and properties:
            # Update properties if it already exists
            node.properties.update(properties)
            await sync_to_async(node.save)()
        return node

    @classmethod
    async def add_edge(cls, source_name: str, target_name: str, relation_type: str):
        source = await sync_to_async(InfrastructureNode.objects.filter(name=source_name).first)()
        target = await sync_to_async(InfrastructureNode.objects.filter(name=target_name).first)()
        
        if source and target:
            edge, _ = await sync_to_async(InfrastructureEdge.objects.get_or_create)(
                source=source, target=target, relation_type=relation_type
            )
            return edge
        return None

    @classmethod
    async def get_dependencies(cls, node_name: str, max_depth: int = 3):
        """Recursively get dependencies of a node."""
        # Simple BFS
        visited = set()
        queue = [(node_name, 0)]
        results = []
        
        # We need synchronous wrapper to traverse
        def _traverse():
            node = InfrastructureNode.objects.filter(name=node_name).first()
            if not node:
                return []
                
            q = [(node, 0)]
            v = set([node.id])
            res = []
            
            while q:
                curr_node, depth = q.pop(0)
                res.append({
                    'name': curr_node.name,
                    'type': curr_node.node_type,
                    'properties': curr_node.properties,
                    'depth': depth
                })
                
                if depth < max_depth:
                    edges = InfrastructureEdge.objects.filter(source=curr_node).select_related('target')
                    for edge in edges:
                        if edge.target.id not in v:
                            v.add(edge.target.id)
                            q.append((edge.target, depth + 1))
            return res
            
        return await sync_to_async(_traverse)()

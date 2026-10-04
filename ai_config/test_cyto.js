const cytoscape = require('cytoscape');

let elements = {"nodes":[{"data":{"id":"layer_network","label":"Network Layer"}},{"data":{"id":"avahi-daemon","label":"avahi-daemon","parent":"layer_network","type":"service","port":43879,"status":"active"}}],"edges":[{"data":{"source":"avahi-daemon","target":"NetworkManager","label":"Dependency","id":"c3f11878-c2a3-4d06-a9f1-d1a4ff4adae9"}}]};

if (elements.nodes && elements.edges) {
  const nodeIds = new Set();
  elements.nodes.forEach(n => { if (n.data && n.data.id) nodeIds.add(n.data.id); });
  
  elements.edges = elements.edges.filter(e => {
    if (!e.data || !e.data.source || !e.data.target) return false;
    if (!nodeIds.has(e.data.source)) {
      elements.nodes.push({ data: { id: e.data.source, label: e.data.source } });
      nodeIds.add(e.data.source);
    }
    if (!nodeIds.has(e.data.target)) {
      elements.nodes.push({ data: { id: e.data.target, label: e.data.target } });
      nodeIds.add(e.data.target);
    }
    return true;
  });
}

try {
  let cy = cytoscape({
    elements: elements,
    headless: true
  });
  console.log("Success! Nodes: " + cy.nodes().length + " Edges: " + cy.edges().length);
} catch(e) {
  console.log("Error: " + e.message);
}

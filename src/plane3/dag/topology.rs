//! Kahn topological sort verifying DAG acyclicity in `O(|V| + |E|)`.

use std::collections::{HashMap, VecDeque};

/// Compute topological ordering or return `Err("cyclic_dag")` if a cycle exists.
pub fn kahn_sort(nodes: &[String], deps: &HashMap<String, Vec<String>>) -> Result<Vec<String>, String> {
    let mut in_deg: HashMap<&str, usize> = nodes.iter().map(|n| (n.as_str(), 0)).collect();
    let mut adj: HashMap<&str, Vec<&str>> = HashMap::new();

    for n in nodes {
        if let Some(ds) = deps.get(n) {
            for d in ds {
                if !in_deg.contains_key(d.as_str()) {
                    return Err(format!("missing_dep:{d}"));
                }
                adj.entry(d.as_str()).or_default().push(n.as_str());
                if let Some(v) = in_deg.get_mut(n.as_str()) {
                    *v += 1;
                }
            }
        }
    }

    let mut q: VecDeque<&str> = in_deg
        .iter()
        .filter(|(_, &deg)| deg == 0)
        .map(|(&k, _)| k)
        .collect();
    let mut order = Vec::with_capacity(nodes.len());
    while let Some(u) = q.pop_front() {
        order.push(u.to_string());
        if let Some(children) = adj.get(u) {
            for &v in children {
                if let Some(deg) = in_deg.get_mut(v) {
                    *deg -= 1;
                    if *deg == 0 {
                        q.push_back(v);
                    }
                }
            }
        }
    }
    if order.len() != nodes.len() {
        return Err("cyclic_dag_detected".into());
    }
    Ok(order)
}

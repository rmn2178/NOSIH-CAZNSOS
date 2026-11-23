//! Static abstract-interpretation Information Flow Control (IFC) over Integrity x Confidentiality.

use crate::plane3::dag::topology::kahn_sort;
use crate::types::confidentiality::ConfidentialityRank;
use crate::types::integrity::IntegrityRank;
use std::collections::HashMap;

/// Static DAG node descriptor for pre-execution IFC checking.
#[derive(Debug, Clone)]
pub struct IfcNode {
    /// Node ID.
    pub id: String,
    /// Origin integrity.
    pub integrity: IntegrityRank,
    /// Origin confidentiality.
    pub confidentiality: ConfidentialityRank,
    /// True if this node is a privileged sink that forbids `Untrusted` data.
    pub privileged_sink: bool,
    /// Upstream dependency node IDs.
    pub deps: Vec<String>,
}

/// Verify acyclicity and static IFC soundness before capability minting.
pub fn verify_ifc_dag(nodes: &[IfcNode]) -> Result<Vec<String>, String> {
    let ids: Vec<String> = nodes.iter().map(|n| n.id.clone()).collect();
    let deps_map: HashMap<String, Vec<String>> =
        nodes.iter().map(|n| (n.id.clone(), n.deps.clone())).collect();
    let order = kahn_sort(&ids, &deps_map)?;
    let by_id: HashMap<&str, &IfcNode> = nodes.iter().map(|n| (n.id.as_str(), n)).collect();
    let mut eff_i: HashMap<String, IntegrityRank> = HashMap::new();

    for id in &order {
        let Some(node) = by_id.get(id.as_str()) else {
            continue;
        };
        let mut cur = node.integrity;
        for d in &node.deps {
            if let Some(&di) = eff_i.get(d) {
                cur = cur.join(di);
            }
        }
        eff_i.insert(id.clone(), cur);
        if node.privileged_sink && cur == IntegrityRank::Untrusted {
            return Err(format!("ifc_tainted_sink:{}", node.id));
        }
    }
    Ok(order)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tainted_sink_rejected() {
        let nodes = vec![
            IfcNode {
                id: "email".into(),
                integrity: IntegrityRank::Untrusted,
                confidentiality: ConfidentialityRank::Public,
                privileged_sink: false,
                deps: vec![],
            },
            IfcNode {
                id: "sink".into(),
                integrity: IntegrityRank::SignedErp,
                confidentiality: ConfidentialityRank::ConfidentialFin,
                privileged_sink: true,
                deps: vec!["email".into()],
            },
        ];
        assert!(verify_ifc_dag(&nodes).is_err());
    }
}

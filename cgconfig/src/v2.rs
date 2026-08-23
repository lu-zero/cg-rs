//! Bridge from legacy libcgroup definitions to a **cgroup v2** leaf plan.
//!
//! v1 configs speak of per-controller hierarchies; under the unified v2
//! hierarchy every group is simply a directory below the mount point and
//! "controllers with blocks on this node" becomes the
//! `cgroup.subtree_control` set. This module performs that translation and
//! expands `%` placeholders with an [`Identity`] supplied by the caller.
//!
//! ```no_run
//! use cgconfig::{parse_cgconfig, parse_cgrules, Identity, first_rule, plan_template};
//!
//! let cfg = parse_cgconfig("template students/%u { cpu { } perm { task { uid = %u; gid = students; } admin { dperm = 750; } } }").unwrap();
//! let rules = parse_cgrules("@students * students/%u").unwrap();
//! let me = Identity { name: "laura".into(), uid: "1001".into(),
//!                     gid: "1500".into(), group: "students".into(),
//!                     ..Default::default() };
//! let rule = first_rule(&rules, &me.name, &[me.group.clone()], None).unwrap();
//! let leaf = plan_template(&cfg, &rule.destination.0, &me).unwrap();
//! assert_eq!(leaf.path, "students/laura");
//! ```

use crate::model::{ConfigFile, Identity, Node};

/// A concrete leaf to create under the (single) v2 mount point.
///
/// Ownership strings stay symbolic (`root`, `%u` already expanded); resolve
/// them with your passwd/group layer.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct LeafPlan {
    /// Path relative to the mount point, placeholders expanded.
    pub path: String,
    /// `perm.task.uid`, expanded. `None` → consumer default (root).
    pub task_uid: Option<String>,
    /// `perm.task.gid`, expanded. `None` → consumer default (root).
    pub task_gid: Option<String>,
    /// `perm.task.fperm` — mode for `cgroup.procs` and friends.
    pub tasks_file_mode: Option<u32>,
    /// `perm.admin.uid`, expanded. `None` → consumer default (root).
    pub owner_uid: Option<String>,
    /// `perm.admin.gid`, expanded. `None` → consumer default (root).
    pub owner_gid: Option<String>,
    /// `perm.admin.dperm` — directory mode.
    pub dir_mode: Option<u32>,
    /// `perm.admin.fperm` — mode for the remaining control files.
    pub file_mode: Option<u32>,
    /// Distinct controllers with a block on this node → `subtree_control`.
    pub subtree_control: Vec<String>,
    /// `(controller, param, value)` triples, file order. Mostly meaningful as
    /// documentation under v2; consumers decide what to apply.
    pub params: Vec<(String, String, String)>,
}

/// Expand one `group` definition (falls back to the `default` perm section).
pub fn plan_group(cfg: &ConfigFile, name: &str, id: &Identity) -> Option<LeafPlan> {
    let node = cfg.find_group(name)?;
    Some(plan_node(cfg, node, id))
}

/// Expand one `template` definition by exact template name.
///
/// Per cgconfig.conf(5), templates do **not** inherit the `default` section.
pub fn plan_template(cfg: &ConfigFile, name: &str, id: &Identity) -> Option<LeafPlan> {
    let node = cfg.find_template(name)?;
    Some(plan_node_perm(
        node.perm.clone().unwrap_or_default(),
        node,
        id,
    ))
}

fn plan_node(cfg: &ConfigFile, node: &Node, id: &Identity) -> LeafPlan {
    plan_node_perm(cfg.effective_perm(node), node, id)
}

fn plan_node_perm(perm: crate::model::Perm, node: &Node, id: &Identity) -> LeafPlan {
    let ex = |s: &Option<String>| {
        s.as_ref()
            .map(|v| id.expand(&crate::model::Template(v.clone())))
    };
    LeafPlan {
        path: id.expand(&crate::model::Template(node.name.clone())),
        task_uid: ex(&perm.task.uid),
        task_gid: ex(&perm.task.gid),
        tasks_file_mode: perm.task.fperm,
        owner_uid: ex(&perm.admin.uid),
        owner_gid: ex(&perm.admin.gid),
        dir_mode: perm.admin.dperm,
        file_mode: perm.admin.fperm,
        subtree_control: node.controllers.clone(),
        params: node.params.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cgconfig::parse_cgconfig;

    fn id() -> Identity {
        Identity {
            name: "lu_zero".into(),
            uid: "1000".into(),
            gid: "10".into(),
            group: "wheel".into(),
            pid: "4242".into(),
            ..Default::default()
        }
    }

    #[test]
    fn plans_template_leaf() {
        let text = include_str!("../examples/students.cgconfig.conf");
        let cfg = parse_cgconfig(text).unwrap();
        let mut me = id();
        me.group = "students".into();
        let leaf = plan_template(&cfg, "students/%u", &me).unwrap();

        assert_eq!(leaf.path, "students/lu_zero");
        assert_eq!(leaf.task_uid.as_deref(), Some("lu_zero"));
        assert_eq!(leaf.task_gid.as_deref(), Some("students"));
        assert_eq!(leaf.tasks_file_mode, Some(0o775));
        assert_eq!(leaf.owner_uid.as_deref(), Some("root"));
        assert_eq!(leaf.dir_mode, Some(0o750));
        assert!(leaf.subtree_control.contains(&"cpu".to_owned()));
        assert!(leaf.subtree_control.contains(&"cpuacct".to_owned()));
    }

    #[test]
    fn group_falls_back_to_default_perm() {
        let text = r#"
default { perm { admin { uid = root; gid = operator; dperm = 755; } } }
group users/%u { memory { } }
"#;
        let cfg = parse_cgconfig(text).unwrap();
        let leaf = plan_group(&cfg, "users/%u", &id()).unwrap();
        assert_eq!(leaf.path, "users/lu_zero");
        assert_eq!(leaf.owner_gid.as_deref(), Some("operator"));
        assert_eq!(leaf.dir_mode, Some(0o755));
        assert_eq!(leaf.subtree_control, vec!["memory".to_owned()]);
    }

    #[test]
    fn missing_node_is_none() {
        let cfg = parse_cgconfig("").unwrap();
        assert!(plan_template(&cfg, "nope", &id()).is_none());
        assert!(plan_group(&cfg, "nope", &id()).is_none());
    }
}

//! Network interfaces, for choosing where to join multicast groups: by name
//! ("en0", "eth1") or by IPv4 address.

use std::net::Ipv4Addr;

/// One IPv4 address of a network interface.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Iface {
    pub name: String,
    pub ip: Ipv4Addr,
    pub netmask: Ipv4Addr,
    /// The subnet's broadcast address, where the OS reports one.
    pub broadcast: Option<Ipv4Addr>,
    pub loopback: bool,
    pub up: bool,
}

/// Every IPv4 address on every interface, in the order the OS lists them.
pub fn list() -> std::io::Result<Vec<Iface>> {
    Ok(if_addrs::get_if_addrs()?
        .into_iter()
        .filter_map(|i| match &i.addr {
            if_addrs::IfAddr::V4(a) => Some(Iface {
                name: i.name.clone(),
                ip: a.ip,
                netmask: a.netmask,
                broadcast: a.broadcast,
                loopback: i.is_loopback(),
                up: i.is_oper_up(),
            }),
            _ => None,
        })
        .collect())
}

/// An interface's IPv4 address from an IPv4 literal or an interface name.
/// A name with several addresses uses its first.
pub fn resolve(spec: &str) -> Result<Ipv4Addr, String> {
    if let Ok(ip) = spec.parse::<Ipv4Addr>() {
        return Ok(ip);
    }
    let all = list().map_err(|e| format!("cannot list network interfaces: {e}"))?;
    all.iter().find(|i| i.name == spec).map(|i| i.ip).ok_or_else(|| {
        let names: Vec<&str> = all.iter().map(|i| i.name.as_str()).collect();
        format!(
            "no interface '{spec}' with an IPv4 address (have: {}; see `nn-server interfaces`)",
            names.join(", ")
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loopback_resolves_by_name_and_address() {
        let lo = list()
            .unwrap()
            .into_iter()
            .find(|i| i.loopback)
            .expect("a loopback interface");
        assert_eq!(resolve(&lo.name).unwrap(), lo.ip);
        assert_eq!(resolve("127.0.0.1").unwrap(), Ipv4Addr::LOCALHOST);
        assert!(resolve("no-such-interface-0")
            .unwrap_err()
            .contains("nn-server interfaces"));
    }
}

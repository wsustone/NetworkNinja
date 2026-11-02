//! Friendly names for senders and simulations ("VBS4 host", "JSAF cell B"),
//! shown wherever the dashboard and reports would print a bare address or
//! site:application. Kept as `[[sender]]` blocks in the `--config` file:
//!
//! ```toml
//! [[sender]]
//! name = "VBS4 host"
//! address = "10.0.5.10"        # or "10.0.5.10:3000" for one port
//!
//! [[sender]]
//! name = "JSAF cell B"
//! simulation = "9:9"           # site:application, or a whole site: "9"
//! ```

use std::fmt;
use std::net::IpAddr;

/// What a name is for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Target {
    /// A sender's address, on any port or one.
    Address(IpAddr, Option<u16>),
    /// A DIS simulation (site:application), or every application of a site.
    Simulation(u16, Option<u16>),
}

impl fmt::Display for Target {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Target::Address(ip, None) => write!(f, "{ip}"),
            Target::Address(IpAddr::V6(ip), Some(p)) => write!(f, "[{ip}]:{p}"),
            Target::Address(ip, Some(p)) => write!(f, "{ip}:{p}"),
            Target::Simulation(s, None) => write!(f, "{s}"),
            Target::Simulation(s, Some(a)) => write!(f, "{s}:{a}"),
        }
    }
}

impl Target {
    /// `"10.0.5.10"`, `"10.0.5.10:3000"`, `"[::1]:3000"` as an address.
    pub fn address(text: &str) -> Result<Target, String> {
        let t = text.trim();
        if let Ok(ip) = t.parse::<IpAddr>() {
            return Ok(Target::Address(ip, None));
        }
        let sa: std::net::SocketAddr = t
            .parse()
            .map_err(|_| format!("'{text}' isn't an IP address or address:port"))?;
        Ok(Target::Address(sa.ip(), Some(sa.port())))
    }

    /// `"9:9"` (site:application) or `"9"` (a whole site) as a simulation.
    pub fn simulation(text: &str) -> Result<Target, String> {
        let n = |s: &str| {
            s.trim()
                .parse::<u16>()
                .ok()
                .filter(|v| (1..0xffff).contains(v))
                .ok_or_else(|| format!("'{text}' isn't a site:application (1-65534)"))
        };
        match text.split_once(':') {
            Some((s, a)) => Ok(Target::Simulation(n(s)?, Some(n(a)?))),
            None => Ok(Target::Simulation(n(text)?, None)),
        }
    }

    /// The config key this target is written under.
    pub fn key(&self) -> &'static str {
        match self {
            Target::Address(..) => "address",
            Target::Simulation(..) => "simulation",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SenderName {
    pub name: String,
    pub target: Target,
}

/// The names in force, most specific match first when looked up.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Names(pub Vec<SenderName>);

impl Names {
    /// Name `target`, replacing any name it had; an empty name removes it.
    pub fn set(&mut self, target: Target, name: &str) {
        self.0.retain(|n| n.target != target);
        let name = name.trim();
        if !name.is_empty() {
            self.0.push(SenderName {
                name: name.to_string(),
                target,
            });
        }
    }

    /// The name of a sender address (`ip:port`): its exact port's name, else
    /// its address's.
    pub fn of_sender(&self, addr: &str) -> Option<&str> {
        let sa: std::net::SocketAddr = addr.parse().ok()?;
        let find = |t: Target| self.0.iter().find(|n| n.target == t).map(|n| n.name.as_str());
        find(Target::Address(sa.ip(), Some(sa.port()))).or_else(|| find(Target::Address(sa.ip(), None)))
    }

    /// The name of a simulation (`site:app`): its own, else its site's.
    pub fn of_simulation(&self, sim: &str) -> Option<&str> {
        let (s, a) = sim.split_once(':')?;
        let (s, a) = (s.parse().ok()?, a.parse().ok()?);
        let find = |t: Target| self.0.iter().find(|n| n.target == t).map(|n| n.name.as_str());
        find(Target::Simulation(s, Some(a))).or_else(|| find(Target::Simulation(s, None)))
    }

    /// `[[sender]]` blocks, in config-file form.
    pub fn to_toml(&self) -> String {
        let q = |s: &str| format!("\"{}\"", s.replace('\\', "\\\\").replace('"', "\\\""));
        self.0
            .iter()
            .map(|n| {
                format!(
                    "[[sender]]\nname = {}\n{} = {}\n\n",
                    q(&n.name),
                    n.target.key(),
                    q(&n.target.to_string())
                )
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_most_specific_name_wins() {
        let mut n = Names::default();
        n.set(Target::address("10.0.5.10").unwrap(), "VBS4 host");
        n.set(Target::address("10.0.5.10:3001").unwrap(), "VBS4 radio");
        n.set(Target::simulation("9").unwrap(), "Site 9");
        n.set(Target::simulation("9:2").unwrap(), "JSAF cell B");
        assert_eq!(n.of_sender("10.0.5.10:3000"), Some("VBS4 host"));
        assert_eq!(n.of_sender("10.0.5.10:3001"), Some("VBS4 radio"));
        assert_eq!(n.of_sender("10.0.5.11:3000"), None);
        assert_eq!(n.of_simulation("9:2"), Some("JSAF cell B"));
        assert_eq!(n.of_simulation("9:7"), Some("Site 9"));
        assert_eq!(n.of_simulation("8:2"), None);
        // Renaming replaces; an empty name removes.
        n.set(Target::simulation("9:2").unwrap(), "JSAF B");
        assert_eq!(n.of_simulation("9:2"), Some("JSAF B"));
        n.set(Target::simulation("9:2").unwrap(), " ");
        assert_eq!(n.of_simulation("9:2"), Some("Site 9"));
    }

    #[test]
    fn targets_parse_and_print_back() {
        for t in ["10.0.5.10", "10.0.5.10:3000", "[::1]:3000", "::1"] {
            assert_eq!(Target::address(t).unwrap().to_string(), t);
        }
        for t in ["9", "9:2"] {
            assert_eq!(Target::simulation(t).unwrap().to_string(), t);
        }
        assert!(Target::address("vbs4").is_err());
        assert!(Target::simulation("0:1").is_err());
        assert!(Target::simulation("9:65535").is_err());
    }
}

use crate::{
    db::SecurityPolicyRecord,
    error::{AppError, AppResult},
    util,
};
use std::net::IpAddr;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustedNetwork {
    addr: IpAddr,
    prefix: u8,
}

pub trait TrustedNetworkPolicy {
    fn trusted_networks(&self) -> AppResult<Vec<TrustedNetwork>>;
    fn is_trusted_ip(&self, ip: Option<&str>) -> AppResult<bool>;
    fn requires_mfa_for_ip(&self, ip: Option<&str>) -> AppResult<bool>;
}

impl TrustedNetworkPolicy for SecurityPolicyRecord {
    fn trusted_networks(&self) -> AppResult<Vec<TrustedNetwork>> {
        networks_from_json(&self.trusted_ip_cidrs, "trusted networks")
    }

    fn is_trusted_ip(&self, ip: Option<&str>) -> AppResult<bool> {
        let Some(ip) = ip.and_then(parse_ip) else {
            return Ok(false);
        };
        Ok(self
            .trusted_networks()?
            .iter()
            .any(|network| network.contains(ip)))
    }

    fn requires_mfa_for_ip(&self, ip: Option<&str>) -> AppResult<bool> {
        Ok(self.require_mfa_outside_trusted_networks != 0 && !self.is_trusted_ip(ip)?)
    }
}

pub fn normalize_trusted_networks(values: Vec<String>) -> AppResult<Vec<String>> {
    normalize_networks(values, "trusted network")
}

pub fn normalize_networks(values: Vec<String>, label: &str) -> AppResult<Vec<String>> {
    let mut networks = Vec::new();
    for value in values {
        let value = value.trim();
        if value.is_empty() {
            continue;
        }
        let network = parse_network(value, label)?;
        let normalized = network.to_string();
        if !networks.iter().any(|existing| existing == &normalized) {
            networks.push(normalized);
        }
    }
    Ok(networks)
}

pub fn trusted_networks_from_json(value: &str) -> AppResult<Vec<TrustedNetwork>> {
    networks_from_json(value, "trusted networks")
}

pub fn networks_from_json(value: &str, label: &str) -> AppResult<Vec<TrustedNetwork>> {
    let values = util::from_json::<Vec<String>>(value)
        .map_err(|err| AppError::BadRequest(format!("{label} are invalid: {err}")))?;
    values
        .into_iter()
        .map(|value| parse_network(&value, label))
        .collect()
}

pub fn ip_in_networks(ip: Option<&str>, networks: &[TrustedNetwork]) -> bool {
    let Some(ip) = ip.and_then(parse_ip) else {
        return false;
    };
    networks.iter().any(|network| network.contains(ip))
}

fn parse_network(value: &str, label: &str) -> AppResult<TrustedNetwork> {
    let value = value.trim();
    let (addr, prefix) = match value.split_once('/') {
        Some((addr, prefix)) => {
            let addr = parse_ip(addr)
                .ok_or_else(|| AppError::BadRequest(format!("{label} has invalid IP: {value}")))?;
            let prefix = prefix.parse::<u8>().map_err(|_| {
                AppError::BadRequest(format!("{label} has invalid prefix: {value}"))
            })?;
            (addr, prefix)
        }
        None => {
            let addr = parse_ip(value)
                .ok_or_else(|| AppError::BadRequest(format!("{label} has invalid IP: {value}")))?;
            let prefix = match addr {
                IpAddr::V4(_) => 32,
                IpAddr::V6(_) => 128,
            };
            (addr, prefix)
        }
    };
    let max_prefix = match addr {
        IpAddr::V4(_) => 32,
        IpAddr::V6(_) => 128,
    };
    if prefix > max_prefix {
        return Err(AppError::BadRequest(format!(
            "{label} prefix is too large: {value}"
        )));
    }
    Ok(TrustedNetwork { addr, prefix })
}

fn parse_ip(value: &str) -> Option<IpAddr> {
    value.trim().parse::<IpAddr>().ok()
}

impl TrustedNetwork {
    pub fn contains(&self, ip: IpAddr) -> bool {
        match (self.addr, ip) {
            (IpAddr::V4(network), IpAddr::V4(ip)) => prefix_match(
                u32::from(network) as u128,
                u32::from(ip) as u128,
                self.prefix,
                32,
            ),
            (IpAddr::V6(network), IpAddr::V6(ip)) => {
                prefix_match(u128::from(network), u128::from(ip), self.prefix, 128)
            }
            _ => false,
        }
    }
}

impl std::fmt::Display for TrustedNetwork {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let full_prefix = match self.addr {
            IpAddr::V4(_) => 32,
            IpAddr::V6(_) => 128,
        };
        if self.prefix == full_prefix {
            write!(formatter, "{}", self.addr)
        } else {
            write!(formatter, "{}/{}", self.addr, self.prefix)
        }
    }
}

fn prefix_match(network: u128, ip: u128, prefix: u8, bits: u8) -> bool {
    if prefix == 0 {
        return true;
    }
    let shift = bits - prefix;
    (network >> shift) == (ip >> shift)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trusted_networks_support_cidr_and_exact_ips() {
        let networks = normalize_trusted_networks(vec![
            "10.0.0.0/8".to_string(),
            "192.168.1.10".to_string(),
            "2001:db8::/32".to_string(),
        ])
        .unwrap();
        assert_eq!(
            networks,
            vec!["10.0.0.0/8", "192.168.1.10", "2001:db8::/32"]
        );
        let parsed = networks
            .iter()
            .map(|value| parse_network(value, "trusted network").unwrap())
            .collect::<Vec<_>>();
        assert!(
            parsed
                .iter()
                .any(|network| network.contains(parse_ip("10.2.3.4").unwrap()))
        );
        assert!(
            parsed
                .iter()
                .any(|network| network.contains(parse_ip("192.168.1.10").unwrap()))
        );
        assert!(
            parsed
                .iter()
                .any(|network| network.contains(parse_ip("2001:db8::1").unwrap()))
        );
        assert!(
            !parsed
                .iter()
                .any(|network| network.contains(parse_ip("172.16.0.1").unwrap()))
        );
    }

    #[test]
    fn invalid_prefix_is_rejected() {
        assert!(normalize_trusted_networks(vec!["10.0.0.0/99".to_string()]).is_err());
        assert!(normalize_trusted_networks(vec!["not-an-ip".to_string()]).is_err());
    }
}

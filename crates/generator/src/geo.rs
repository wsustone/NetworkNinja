//! Minimal WGS84 helpers: geodetic ↔ geocentric (ECEF).

use nn_decode::{Vec3f, WorldCoord};

const A: f64 = 6_378_137.0; // semi-major axis, m
const F: f64 = 1.0 / 298.257_223_563;
const E2: f64 = F * (2.0 - F);

/// Latitude/longitude in degrees and height in metres to ECEF metres.
pub fn lla_to_ecef(lat_deg: f64, lon_deg: f64, h: f64) -> WorldCoord {
    let (lat, lon) = (lat_deg.to_radians(), lon_deg.to_radians());
    let n = A / (1.0 - E2 * lat.sin().powi(2)).sqrt();
    WorldCoord {
        x: (n + h) * lat.cos() * lon.cos(),
        y: (n + h) * lat.cos() * lon.sin(),
        z: (n * (1.0 - E2) + h) * lat.sin(),
    }
}

/// Rotate a local east/north/up vector at (lat, lon) into ECEF axes.
pub fn enu_to_ecef(lat_deg: f64, lon_deg: f64, e: f64, n: f64, u: f64) -> Vec3f {
    let (lat, lon) = (lat_deg.to_radians(), lon_deg.to_radians());
    let (sl, cl, so, co) = (lat.sin(), lat.cos(), lon.sin(), lon.cos());
    Vec3f {
        x: (-so * e - sl * co * n + cl * co * u) as f32,
        y: (co * e - sl * so * n + cl * so * u) as f32,
        z: (cl * n + sl * u) as f32,
    }
}

/// Metres per degree of latitude and of longitude at `lat_deg` (approximate).
pub fn metres_per_degree(lat_deg: f64) -> (f64, f64) {
    let lat = lat_deg.to_radians();
    (111_132.92 - 559.82 * (2.0 * lat).cos(), 111_412.84 * lat.cos())
}

pub fn distance(a: &WorldCoord, b: &WorldCoord) -> f64 {
    ((a.x - b.x).powi(2) + (a.y - b.y).powi(2) + (a.z - b.z).powi(2)).sqrt()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn equator_prime_meridian() {
        let p = lla_to_ecef(0.0, 0.0, 0.0);
        assert!((p.x - A).abs() < 1e-6 && p.y.abs() < 1e-6 && p.z.abs() < 1e-6);
    }

    #[test]
    fn small_enu_step_matches_ecef_difference() {
        let (lat, lon) = (36.6, -121.9);
        let (mlat, mlon) = metres_per_degree(lat);
        let a = lla_to_ecef(lat, lon, 10.0);
        let b = lla_to_ecef(lat + 10.0 / mlat, lon + 20.0 / mlon, 10.0);
        let v = enu_to_ecef(lat, lon, 20.0, 10.0, 0.0);
        assert!((b.x - a.x - v.x as f64).abs() < 0.05);
        assert!((b.y - a.y - v.y as f64).abs() < 0.05);
        assert!((b.z - a.z - v.z as f64).abs() < 0.05);
    }
}

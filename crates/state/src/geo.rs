//! Minimal WGS84 helpers: geodetic ↔ geocentric (ECEF).

use nn_decode::{EulerAngles, Vec3f, WorldCoord};

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

/// DIS orientation (Euler angles of the body axes against ECEF, IEEE 1278.1
/// 1.4.3 / Annex E) of a level vehicle at (lat, lon) whose nose points
/// `heading` radians clockwise from north: body x forward, y right, z down.
pub fn heading_to_euler(lat_deg: f64, lon_deg: f64, heading: f64) -> EulerAngles {
    let (sh, ch) = heading.sin_cos();
    let axis = |e: f64, n: f64, u: f64| {
        let v = enu_to_ecef(lat_deg, lon_deg, e, n, u);
        [v.x as f64, v.y as f64, v.z as f64]
    };
    let x = axis(sh, ch, 0.0); // forward
    let y = axis(ch, -sh, 0.0); // right
    let z = axis(0.0, 0.0, -1.0); // down
                                  // Columns of R = Rz(psi) Ry(theta) Rx(phi) are the body axes.
    EulerAngles {
        psi: x[1].atan2(x[0]) as f32,
        theta: (-x[2]).clamp(-1.0, 1.0).asin() as f32,
        phi: y[2].atan2(z[2]) as f32,
    }
}

/// Metres per degree of latitude and of longitude at `lat_deg` (approximate).
pub fn metres_per_degree(lat_deg: f64) -> (f64, f64) {
    let lat = lat_deg.to_radians();
    (111_132.92 - 559.82 * (2.0 * lat).cos(), 111_412.84 * lat.cos())
}

/// ECEF metres to latitude/longitude in degrees and height in metres.
///
/// Uses Bowring's formula with one refinement step; sub-millimetre accurate
/// near the Earth's surface.
pub fn ecef_to_lla(p: &WorldCoord) -> (f64, f64, f64) {
    let b = A * (1.0 - F);
    let ep2 = (A * A - b * b) / (b * b);
    let r = (p.x * p.x + p.y * p.y).sqrt();
    if r < 1e-9 {
        // On the polar axis.
        let lat = if p.z >= 0.0 { 90.0 } else { -90.0 };
        return (lat, 0.0, p.z.abs() - b);
    }
    let lon = p.y.atan2(p.x);
    let mut theta = (p.z * A).atan2(r * b);
    let mut lat = (p.z + ep2 * b * theta.sin().powi(3)).atan2(r - E2 * A * theta.cos().powi(3));
    // One refinement pass using the new latitude.
    theta = ((1.0 - F) * lat.tan()).atan();
    lat = (p.z + ep2 * b * theta.sin().powi(3)).atan2(r - E2 * A * theta.cos().powi(3));
    let n = A / (1.0 - E2 * lat.sin().powi(2)).sqrt();
    let h = r / lat.cos() - n;
    (lat.to_degrees(), lon.to_degrees(), h)
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
    fn ecef_lla_roundtrip() {
        for (lat, lon, h) in [
            (36.6, -121.9, 10.0),
            (-33.9, 151.2, 500.0),
            (0.0, 0.0, 0.0),
            (89.9, 10.0, 1000.0),
            (51.5, -0.1, 11_000.0),
        ] {
            let (la, lo, hh) = ecef_to_lla(&lla_to_ecef(lat, lon, h));
            assert!(
                (la - lat).abs() < 1e-8 && (lo - lon).abs() < 1e-8 && (hh - h).abs() < 1e-3,
                "{lat},{lon},{h} -> {la},{lo},{hh}"
            );
        }
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

    #[test]
    fn heading_to_euler_points_the_body_x_axis_along_the_heading() {
        for (lat, lon) in [(36.6, -121.9), (-33.9, 151.2), (0.0, 0.0), (60.0, 10.0)] {
            for h in [0.0f64, 0.7, 1.9, -2.5] {
                let o = heading_to_euler(lat, lon, h);
                let fwd = crate::dr::body_to_world(
                    &o,
                    &Vec3f {
                        x: 10.0,
                        y: 0.0,
                        z: 0.0,
                    },
                );
                let want = enu_to_ecef(lat, lon, 10.0 * h.sin(), 10.0 * h.cos(), 0.0);
                let err = ((fwd.x - want.x).powi(2) + (fwd.y - want.y).powi(2) + (fwd.z - want.z).powi(2)).sqrt();
                assert!(err < 1e-3, "{lat},{lon} h={h}: {fwd:?} vs {want:?}");
                let down = crate::dr::body_to_world(&o, &Vec3f { x: 0.0, y: 0.0, z: 1.0 });
                let up = enu_to_ecef(lat, lon, 0.0, 0.0, 1.0);
                assert!((down.x + up.x).abs() + (down.y + up.y).abs() + (down.z + up.z).abs() < 1e-4);
            }
        }
    }
}

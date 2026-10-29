//! Dead-reckoning extrapolation (IEEE 1278.1 Annex E algorithms 1–9).
//!
//! World-coordinate algorithms (2–5) are implemented exactly. The body-axis
//! algorithms (6–9) carry acceleration in the entity's body frame; we rotate
//! it into world coordinates with the reported orientation and then use the
//! world formula. That ignores the entity's rotation during the
//! extrapolation interval, which is well inside the position-jump tolerance
//! over the few seconds between updates. Algorithm 0 ("other") and unknown
//! values are treated as constant velocity (FPW), the most common default.

use nn_decode::{EulerAngles, Vec3f, WorldCoord};

/// The kinematic state carried by one Entity State PDU.
#[derive(Debug, Clone, Copy, PartialEq, Default)]
pub struct Kinematics {
    pub location: WorldCoord,
    pub velocity: Vec3f,
    pub acceleration: Vec3f,
    pub orientation: EulerAngles,
    pub algorithm: u8,
}

/// Predicted location `dt` seconds after `k` was reported.
pub fn extrapolate(k: &Kinematics, dt: f64) -> WorldCoord {
    let p = k.location;
    let v = k.velocity;
    let lin = |p: WorldCoord, v: Vec3f| WorldCoord {
        x: p.x + v.x as f64 * dt,
        y: p.y + v.y as f64 * dt,
        z: p.z + v.z as f64 * dt,
    };
    let with_accel = |a: Vec3f| {
        let q = lin(p, v);
        WorldCoord {
            x: q.x + 0.5 * a.x as f64 * dt * dt,
            y: q.y + 0.5 * a.y as f64 * dt * dt,
            z: q.z + 0.5 * a.z as f64 * dt * dt,
        }
    };
    match k.algorithm {
        1 => p,                                                              // static
        4 | 5 => with_accel(k.acceleration),                                 // RVW, FVW
        8 | 9 => with_accel(body_to_world(&k.orientation, &k.acceleration)), // RVB, FVB
        _ => lin(p, v),                                                      // FPW, RPW, FPB, RPB, other
    }
}

/// Rotate a body-frame vector into world (ECEF) axes using DIS Euler angles
/// (psi about z, then theta about y, then phi about x).
pub fn body_to_world(o: &EulerAngles, b: &Vec3f) -> Vec3f {
    let (sp, cp) = (o.psi as f64).sin_cos();
    let (st, ct) = (o.theta as f64).sin_cos();
    let (sf, cf) = (o.phi as f64).sin_cos();
    let (x, y, z) = (b.x as f64, b.y as f64, b.z as f64);
    // R = Rz(psi) * Ry(theta) * Rx(phi)
    let r = [
        [ct * cp, sf * st * cp - cf * sp, cf * st * cp + sf * sp],
        [ct * sp, sf * st * sp + cf * cp, cf * st * sp - sf * cp],
        [-st, sf * ct, cf * ct],
    ];
    Vec3f {
        x: (r[0][0] * x + r[0][1] * y + r[0][2] * z) as f32,
        y: (r[1][0] * x + r[1][1] * y + r[1][2] * z) as f32,
        z: (r[2][0] * x + r[2][1] * y + r[2][2] * z) as f32,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn k(algorithm: u8) -> Kinematics {
        Kinematics {
            location: WorldCoord {
                x: 100.0,
                y: 200.0,
                z: 300.0,
            },
            velocity: Vec3f {
                x: 10.0,
                y: 0.0,
                z: -2.0,
            },
            acceleration: Vec3f { x: 0.0, y: 4.0, z: 0.0 },
            orientation: EulerAngles::default(),
            algorithm,
        }
    }

    #[test]
    fn static_stays_put() {
        assert_eq!(extrapolate(&k(1), 10.0), k(1).location);
    }

    #[test]
    fn constant_velocity() {
        let p = extrapolate(&k(2), 2.0);
        assert_eq!((p.x, p.y, p.z), (120.0, 200.0, 296.0));
    }

    #[test]
    fn with_acceleration() {
        let p = extrapolate(&k(5), 2.0);
        assert_eq!((p.x, p.y, p.z), (120.0, 208.0, 296.0));
    }

    #[test]
    fn body_frame_acceleration_is_rotated() {
        // Yaw 90°: body x (forward) points along world y.
        let mut kk = k(9);
        kk.acceleration = Vec3f { x: 4.0, y: 0.0, z: 0.0 };
        kk.orientation = EulerAngles {
            psi: std::f32::consts::FRAC_PI_2,
            theta: 0.0,
            phi: 0.0,
        };
        let p = extrapolate(&kk, 2.0);
        assert!((p.x - 120.0).abs() < 1e-4 && (p.y - 208.0).abs() < 1e-4 && (p.z - 296.0).abs() < 1e-4);
    }

    #[test]
    fn rotation_is_orthonormal() {
        let o = EulerAngles {
            psi: 0.7,
            theta: -0.3,
            phi: 1.1,
        };
        let v = body_to_world(
            &o,
            &Vec3f {
                x: 3.0,
                y: 4.0,
                z: 12.0,
            },
        );
        let len = ((v.x * v.x + v.y * v.y + v.z * v.z) as f64).sqrt();
        assert!((len - 13.0).abs() < 1e-4);
    }
}

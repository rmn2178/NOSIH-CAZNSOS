#![allow(clippy::needless_range_loop)]
//! Pure-Rust 10D Discounted Primal-Dual LinUCB router over 5 model classes.

const DIM: usize = 10;
const CONSTRAINTS: usize = 3; // [latency, cost, carbon]

/// Discounted Primal-Dual LinUCB contextual bandit router.
#[derive(Debug, Clone)]
pub struct CaDpdLinUcb {
    num_arms: usize,
    gamma: f64,
    lambda: f64,
    alpha: f64,
    budgets: [f64; CONSTRAINTS],
    dual_lr: f64,
    dual_max: f64,
    v: Vec<[[f64; DIM]; DIM]>,
    v_inv: Vec<[[f64; DIM]; DIM]>,
    u_r: Vec<[f64; DIM]>,
    u_c: Vec<[[f64; DIM]; CONSTRAINTS]>,
    theta: Vec<[f64; DIM]>,
    phi: Vec<[[f64; DIM]; CONSTRAINTS]>,
    /// Projected online Lagrangian dual multipliers.
    pub mu: [f64; CONSTRAINTS],
    /// Total observed routing updates.
    pub t: u64,
}

fn eye(scale: f64) -> [[f64; DIM]; DIM] {
    let mut m = [[0.0; DIM]; DIM];
    for (i, row) in m.iter_mut().enumerate() {
        row[i] = scale;
    }
    m
}

fn dot(a: &[f64; DIM], b: &[f64; DIM]) -> f64 {
    a.iter().zip(b.iter()).map(|(x, y)| x * y).sum()
}

fn mv(m: &[[f64; DIM]; DIM], x: &[f64; DIM]) -> [f64; DIM] {
    let mut out = [0.0; DIM];
    for i in 0..DIM {
        out[i] = dot(&m[i], x);
    }
    out
}

fn inv10(mat: &[[f64; DIM]; DIM]) -> [[f64; DIM]; DIM] {
    let mut a = *mat;
    let mut inv = eye(1.0);
    for col in 0..DIM {
        let mut piv = col;
        let mut best = a[col][col].abs();
        for (r, row) in a.iter().enumerate().skip(col + 1) {
            if row[col].abs() > best {
                best = row[col].abs();
                piv = r;
            }
        }
        if best < 1e-12 {
            a[col][col] = 1e-6;
        } else if piv != col {
            a.swap(col, piv);
            inv.swap(col, piv);
        }
        let d = a[col][col];
        for j in 0..DIM {
            a[col][j] /= d;
            inv[col][j] /= d;
        }
        for r in 0..DIM {
            if r == col {
                continue;
            }
            let f = a[r][col];
            if f.abs() > 1e-15 {
                for j in 0..DIM {
                    a[r][j] -= f * a[col][j];
                    inv[r][j] -= f * inv[col][j];
                }
            }
        }
    }
    inv
}

impl CaDpdLinUcb {
    /// Construct with paper defaults (`gamma=0.992`, `budgets=[0.35, 0.35, 0.35]`).
    pub fn new_default() -> Self {
        let num_arms = 5;
        Self {
            num_arms,
            gamma: 0.992,
            lambda: 1.0,
            alpha: 0.65,
            budgets: [0.35, 0.35, 0.35],
            dual_lr: 0.08,
            dual_max: 5.0,
            v: vec![eye(1.0); num_arms],
            v_inv: vec![eye(1.0); num_arms],
            u_r: vec![[0.0; DIM]; num_arms],
            u_c: vec![[[0.0; DIM]; CONSTRAINTS]; num_arms],
            theta: vec![[0.0; DIM]; num_arms],
            phi: vec![[[0.0; DIM]; CONSTRAINTS]; num_arms],
            mu: [0.0; CONSTRAINTS],
            t: 0,
        }
    }

    /// Select arm maximizing `UCB_r(x) - mu . (LCB_c(x) - b) - pcsp_penalties[a]`.
    pub fn select(&self, x: &[f64; DIM], feasible: &[usize], pcsp_penalties: &[f64; 5]) -> usize {
        let mut best_arm = feasible.first().copied().unwrap_or(2);
        let mut best_score = f64::NEG_INFINITY;
        for &a in feasible {
            if a >= self.num_arms {
                continue;
            }
            let mean_r = dot(&self.theta[a], x);
            let vix = mv(&self.v_inv[a], x);
            let width = self.alpha * dot(x, &vix).max(0.0).sqrt();
            let ucb = mean_r + width;
            let mut dual = 0.0;
            for m in 0..CONSTRAINTS {
                let lcb = (dot(&self.phi[a][m], x) - 0.5 * width).clamp(0.0, 1.0);
                dual += self.mu[m] * (lcb - self.budgets[m]);
            }
            let score = ucb - dual - pcsp_penalties[a];
            if score > best_score {
                best_score = score;
                best_arm = a;
            }
        }
        best_arm
    }

    /// Online discounted ridge update + projected dual ascent.
    pub fn update(&mut self, arm: usize, x: &[f64; DIM], reward: f64, costs: [f64; CONSTRAINTS]) {
        if arm >= self.num_arms {
            return;
        }
        self.t += 1;
        let g = self.gamma;
        let reg = (1.0 - g) * self.lambda;
        for a in 0..self.num_arms {
            for i in 0..DIM {
                self.u_r[a][i] *= g;
                for m in 0..CONSTRAINTS {
                    self.u_c[a][m][i] *= g;
                }
                for j in 0..DIM {
                    self.v[a][i][j] = g * self.v[a][i][j] + if i == j { reg } else { 0.0 };
                }
            }
        }
        let c = [costs[0].clamp(0.0, 1.0), costs[1].clamp(0.0, 1.0), costs[2].clamp(0.0, 1.0)];
        for i in 0..DIM {
            self.u_r[arm][i] += reward * x[i];
            for m in 0..CONSTRAINTS {
                self.u_c[arm][m][i] += c[m] * x[i];
            }
            for j in 0..DIM {
                self.v[arm][i][j] += x[i] * x[j];
            }
        }
        self.v_inv[arm] = inv10(&self.v[arm]);
        self.theta[arm] = mv(&self.v_inv[arm], &self.u_r[arm]);
        for m in 0..CONSTRAINTS {
            self.phi[arm][m] = mv(&self.v_inv[arm], &self.u_c[arm][m]);
            self.mu[m] = (self.mu[m] + self.dual_lr * (c[m] - self.budgets[m])).clamp(0.0, self.dual_max);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dual_updates_project_into_box() {
        let mut b = CaDpdLinUcb::new_default();
        let x = [1.0, 0.5, 0.0, 0.0, 0.0, 0.1, 0.9, 0.5, 0.5, 0.1];
        for _ in 0..200 {
            b.update(4, &x, 1.0, [1.0, 1.0, 1.0]);
        }
        for m in b.mu {
            assert!((0.0..=5.0).contains(&m));
        }
    }
}

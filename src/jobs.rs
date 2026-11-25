use crate::{
    models::{JobStep, JobView},
    util::{one_line, random_token},
};
use chrono::{DateTime, Utc};
use std::sync::Arc;
use tokio::sync::Mutex;

#[derive(Clone, Debug)]
pub struct Job {
    pub id: String,
    pub summary: String,
    pub status: String,
    pub steps: Vec<JobStep>,
    pub started: DateTime<Utc>,
    pub done: DateTime<Utc>,
    pub total: usize,
}

impl Job {
    pub fn new(summary: String, labels: Vec<String>) -> Self {
        let now = Utc::now();
        let total = labels.len();
        Self {
            id: random_token(12),
            summary,
            status: "running".into(),
            steps: labels
                .into_iter()
                .map(|label| JobStep {
                    label,
                    status: "pending".into(),
                    detail: String::new(),
                })
                .collect(),
            started: now,
            done: now,
            total,
        }
    }

    pub fn set(&mut self, i: usize, status: &str, detail: &str) {
        if let Some(s) = self.steps.get_mut(i) {
            s.status = status.into();
            s.detail = one_line(detail, 500);
        }
    }

    pub fn finish(&mut self) {
        self.status = "done".into();
        self.done = Utc::now();
    }

    pub fn view(&self) -> JobView {
        JobView {
            id: self.id.clone(),
            summary: self.summary.clone(),
            status: self.status.clone(),
            steps: self.steps.clone(),
            started: self.started,
            done: self.done,
            total: self.total,
        }
    }
}

#[derive(Clone, Default)]
pub struct JobStore {
    jobs: Arc<Mutex<Vec<Job>>>,
}

impl JobStore {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    pub async fn new_job(&self, summary: String, labels: Vec<String>) -> JobHandle {
        let job = Job::new(summary, labels);
        let mut jobs = self.jobs.lock().await;
        jobs.insert(0, job.clone());
        jobs.truncate(8);
        JobHandle {
            jobs: self.jobs.clone(),
            id: job.id,
        }
    }

    pub async fn views(&self) -> Vec<JobView> {
        self.jobs.lock().await.iter().map(Job::view).collect()
    }

    pub async fn dismiss(&self, id: &str) {
        self.jobs.lock().await.retain(|j| j.id != id);
    }
}

#[derive(Clone)]
pub struct JobHandle {
    jobs: Arc<Mutex<Vec<Job>>>,
    id: String,
}

impl JobHandle {
    pub fn id(&self) -> String {
        self.id.clone()
    }

    pub async fn set(&self, i: usize, status: &str, detail: &str) {
        let mut jobs = self.jobs.lock().await;
        if let Some(j) = jobs.iter_mut().find(|j| j.id == self.id) {
            j.set(i, status, detail);
        }
    }

    pub async fn finish(self) {
        let mut jobs = self.jobs.lock().await;
        if let Some(j) = jobs.iter_mut().find(|j| j.id == self.id) {
            j.finish();
        }
    }
}

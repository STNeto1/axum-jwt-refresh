use serde::Serialize;

#[derive(Debug, Serialize)]
pub struct User {
    pub id: i32,
    pub username: String,
    pub password: String,
}

#[derive(Debug)]
pub struct UserStore {
    pub users: Vec<User>,
}

impl UserStore {
    pub fn new() -> Self {
        let users = vec![User {
            id: 1,
            username: "stneto1".to_string(),
            password: "102030".to_string(),
        }];

        UserStore { users }
    }

    pub fn find_by_username(&self, username: &str) -> Option<&User> {
        self.users.iter().find(|user| user.username == username)
    }

    pub fn find_by_id(&self, id: i32) -> Option<&User> {
        self.users.iter().find(|user| user.id == id)
    }

    pub fn create_new_user(&mut self, username: &str, password: &str) -> &User {
        let id = self.users.len() as i32 + 1;

        let new_user = User {
            id,
            username: username.to_string(),
            password: password.to_string(),
        };

        self.users.push(new_user);

        self.find_by_id(id).unwrap()
    }
}

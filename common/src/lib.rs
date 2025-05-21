#[derive(Debug)]
pub struct Add {
    value: i32,
}

impl Add {
    pub fn new(value: i32) -> Self {
        Add { value }
    }

    pub fn int(&self) -> Add {
        Add::new(self.value + 1)
    }
}

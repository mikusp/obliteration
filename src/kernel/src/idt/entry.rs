/// An entry in the ID table.
#[derive(Debug)]
pub struct Entry<T> {
    name: Option<String>,
    data: T,
    ty: u16,
}

impl<T> Entry<T> {
    pub fn new(name: Option<String>, data: T, ty: u16) -> Self {
        Self { name, data, ty }
    }

    pub fn name(&self) -> &Option<String> {
        &self.name
    }

    pub fn data(&self) -> &T {
        &self.data
    }

    pub fn ty(&self) -> u16 {
        self.ty
    }
}

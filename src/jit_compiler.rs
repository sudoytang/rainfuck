pub trait JitCompiler {
    fn new() -> Self;
    fn compile_and_run(&mut self, code: &str);
}
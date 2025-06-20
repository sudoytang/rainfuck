extern crate libc;
extern crate dynasmrt;
extern crate dynasm;

use std::mem;
use crate::jit_compiler::JitCompiler;
use jit_compiler_arm64::dynasmrt::DynasmApi;
use jit_compiler_arm64::dynasmrt::DynasmLabelApi;

extern "C" fn _getchar() -> i32 {
    let mut tmp_str = String::new();
    std::io::stdin().read_line(&mut tmp_str).unwrap();
    tmp_str.chars().next().unwrap() as i32
}

extern "C" fn _putchar(ch: i32) {
    print!("{}", ch as u8 as char);
}

pub struct JitCompilerARM64 {
}

impl JitCompiler for JitCompilerARM64 {
    fn new() -> Self {
        Self {}
    }

    fn compile_and_run(&mut self, code: &str) {
        // Create a new assembler
        let mut ops = dynasmrt::aarch64::Assembler::new().unwrap();
        let entry = ops.offset();


        let mut bracket_stack = Vec::new();
        
        // Generate function prologue
        dynasm::dynasm!(ops
            // Save caller-saved registers
            ; sub sp, sp, #16
            ; stp x19, x20, [sp]      // Save x19(data base) and x20(data offset)
            
            // x0 contains memory base address, move it to x19
            ; mov x19, x0             // x19 = data base
            ; mov x20, #0             // x20 = 0 (data offset)
        );

        // Parse and compile code
        for ch in code.chars() {
            match ch {
                '>' => {
                    // Move data pointer to the right
                    dynasm::dynasm!(ops
                        ; add x20, x20, #1      // x20++
                    );
                },
                '<' => {
                    // Move data pointer to the left
                    dynasm::dynasm!(ops
                        ; sub x20, x20, #1      // x20--
                    );
                },
                '+' => {
                    // Increment the value at the current cell
                    dynasm::dynasm!(ops
                        ; ldrb w16, [x19, x20]  // w16 = *[x19 + x20]
                        ; add w16, w16, #1      // w16++
                        ; strb w16, [x19, x20]  // *[x19 + x20] = w16
                    );
                },
                '-' => {
                    // Decrement the value at the current cell
                    dynasm::dynasm!(ops
                        ; ldrb w16, [x19, x20]  // w16 = *[x19 + x20]
                        ; sub w16, w16, #1      // w16--
                        ; strb w16, [x19, x20]  // *[x19 + x20] = w16
                    );
                },
                '.' => {
                    // Output the value at the current cell
                    dynasm::dynasm!(ops
                        // Save caller-saved registers
                        ; sub sp, sp, #16
                        ; stp x29, x30, [sp]    // Save frame pointer and return address
                        
                        ; ldrb w0, [x19, x20]   // w0 = *[x19 + x20] (parameter)
                    );
                    
                    // move _putchar to x16
                    let output_fn_ptr = _putchar as *const () as u64;
                    let movz_instr = 0xd2800010u32 | ((output_fn_ptr & 0xffff) as u32) << 5;
                    let movk1_instr = 0xf2a00010u32 | (((output_fn_ptr >> 16) & 0xffff) as u32) << 5;
                    let movk2_instr = 0xf2c00010u32 | (((output_fn_ptr >> 32) & 0xffff) as u32) << 5;
                    let movk3_instr = 0xf2e00010u32 | (((output_fn_ptr >> 48) & 0xffff) as u32) << 5;
                    
                    ops.extend(&[
                        movz_instr as u8, (movz_instr >> 8) as u8, (movz_instr >> 16) as u8, (movz_instr >> 24) as u8,
                        movk1_instr as u8, (movk1_instr >> 8) as u8, (movk1_instr >> 16) as u8, (movk1_instr >> 24) as u8,
                        movk2_instr as u8, (movk2_instr >> 8) as u8, (movk2_instr >> 16) as u8, (movk2_instr >> 24) as u8,
                        movk3_instr as u8, (movk3_instr >> 8) as u8, (movk3_instr >> 16) as u8, (movk3_instr >> 24) as u8,
                    ]);
                    
                    dynasm::dynasm!(ops
                        ; blr x16
                        
                        // Restore registers
                        ; ldp x29, x30, [sp]
                        ; add sp, sp, #16
                    );
                },
                ',' => {
                    // Read input to the current cell
                    dynasm::dynasm!(ops
                        // Save caller-saved registers
                        ; sub sp, sp, #16
                        ; stp x29, x30, [sp]    // Save frame pointer and return address
                    );
                    
                    // move _getchar to x16
                    let input_fn_ptr = _getchar as *const () as u64;
                    let movz_instr = 0xd2800010u32 | ((input_fn_ptr & 0xffff) as u32) << 5;
                    let movk1_instr = 0xf2a00010u32 | (((input_fn_ptr >> 16) & 0xffff) as u32) << 5;
                    let movk2_instr = 0xf2c00010u32 | (((input_fn_ptr >> 32) & 0xffff) as u32) << 5;
                    let movk3_instr = 0xf2e00010u32 | (((input_fn_ptr >> 48) & 0xffff) as u32) << 5;
                    
                    ops.extend(&[
                        movz_instr as u8, (movz_instr >> 8) as u8, (movz_instr >> 16) as u8, (movz_instr >> 24) as u8,
                        movk1_instr as u8, (movk1_instr >> 8) as u8, (movk1_instr >> 16) as u8, (movk1_instr >> 24) as u8,
                        movk2_instr as u8, (movk2_instr >> 8) as u8, (movk2_instr >> 16) as u8, (movk2_instr >> 24) as u8,
                        movk3_instr as u8, (movk3_instr >> 8) as u8, (movk3_instr >> 16) as u8, (movk3_instr >> 24) as u8,
                    ]);
                    
                    dynasm::dynasm!(ops
                        ; blr x16
                        
                        // Store return value to current cell
                        ; strb w0, [x19, x20]   // *[x19 + x20] = w0
                        
                        // Restore registers
                        ; ldp x29, x30, [sp]
                        ; add sp, sp, #16
                    );
                },
                '[' => {
                    // Loop start
                    let loop_start = ops.new_dynamic_label();
                    let loop_end = ops.new_dynamic_label();
                    
                    dynasm::dynasm!(ops
                        ; => loop_start         // Loop start label
                        ; ldrb w16, [x19, x20]  // w16 = *[x19 + x20]
                        ; cmp w16, #0           // Compare w16 with 0
                        ; b.eq => loop_end      // If w16 == 0, jump to loop end
                    );
                    bracket_stack.push((loop_start, loop_end));
                },
                ']' => {
                    // Loop end
                    if let Some((loop_start, loop_end)) = bracket_stack.pop() {
                        dynasm::dynasm!(ops
                            ; b => loop_start   // Jump back to loop start
                            ; => loop_end       // Loop end label
                        );
                    }
                },
                _ => {} // Ignore other characters
            }
        }

        
        // Generate function epilogue
        dynasm::dynasm!(ops
            // Restore registers
            ; ldp x19, x20, [sp]
            ; add sp, sp, #16
            ; ret                      // Return
        );
        
        // Finalize assembly and get executable buffer
        println!("DEBUG HERE");
        let exec_buffer = ops.finalize().unwrap();
        println!("{exec_buffer:?}");
        // Get executable function pointer
        let code_fn: extern "C" fn(*mut u8) = unsafe {
            mem::transmute(exec_buffer.ptr(entry))
        };

        // Allocate memory and run code
        let mut memory: Vec<u8> = vec![0; 30000]; // Standard Brainfuck uses 30000 cells
        code_fn(memory.as_mut_ptr());
    }
}
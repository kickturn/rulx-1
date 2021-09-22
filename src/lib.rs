use detour::GenericDetour;
use std::io;
use std::thread;
mod consts;

static mut GETTOP_HOOK: Option<GenericDetour<fn(i32) -> i32>> = None;
static mut LUA_STATE: i32 = 0;
static mut BASE_ADDR: u32 = 0;
fn hooked_function(data: i32) -> i32 {
    unsafe {
        let gettop = (consts::LUA_GETTOP - 0x00400000) + BASE_ADDR;
        let settop: u32 = (consts::LUA_SETTOP - 0x00400000) + BASE_ADDR;
        let newthread: u32 = (consts::LUA_NEWTHREAD - 0x00400000) + BASE_ADDR;
        match GETTOP_HOOK {
            Some(ref mut hook) => {
                hook.disable().unwrap();

                LUA_STATE = data;
                let new_thread =
                    std::mem::transmute::<*const usize, fn(i32) -> i32>(newthread as *const usize);
                new_thread(data);
                let settop = std::mem::transmute::<*const usize, fn(i32, i32) -> i32>(
                    settop as *const usize,
                );
                settop(data, -2);
                let gettop =
                    std::mem::transmute::<*const usize, fn(i32) -> i32>(gettop as *const usize);
                println!("STATE: {}", LUA_STATE);
                let val = gettop(data);

                return val;
            }
            None => {
                panic!("Could not disable hook");
            }
        }
    }
}

fn entry_point() {
    unsafe {
        BASE_ADDR = winapi::um::libloaderapi::GetModuleHandleA(0 as *const i8) as u32;

        winapi::um::consoleapi::AllocConsole();
        let tolstring: u32 = (consts::LUA_TOLSTRING - 0x00400000) + BASE_ADDR;
        let pcall: u32 = (consts::LUA_PCALL - 0x00400000) + BASE_ADDR;
        let loadbuffer: u32 = (consts::LUA_LOADBUFFER - 0x00400000) + BASE_ADDR;

        println!("Injected!");

        let gettop: u32 = (consts::LUA_GETTOP - 0x00400000) + BASE_ADDR;
        let orig_lua_gettop =
            std::mem::transmute::<*const usize, fn(i32) -> i32>(gettop as *const usize);
        let newthread: u32 = (consts::LUA_NEWTHREAD - 0x00400000) + BASE_ADDR;

        GETTOP_HOOK =
            Some(GenericDetour::<fn(i32) -> i32>::new(orig_lua_gettop, hooked_function).unwrap());
        match GETTOP_HOOK {
            Some(ref mut hook) => {
                hook.enable().unwrap();
                println!("Hooked Lua_GETTOP");
            }
            None => panic!("Could not enable hook"),
        }
        let pcall = std::mem::transmute::<*const usize, fn(i32, i32, i32, i32) -> i32>(
            pcall as *const usize,
        );
        let loadbuffer = std::mem::transmute::<
            *const usize,
            fn(i32, *const u8, usize, *const u8) -> i32,
        >(loadbuffer as *const usize);
        let new_thread =
            std::mem::transmute::<*const usize, fn(i32) -> i32>(newthread as *const usize);
        let tolstring = std::mem::transmute::<*const usize, fn(i32, i32) -> std::ffi::CString>(
            tolstring as *const usize,
        );
        loop {
            let mut input = String::new();

            io::stdin()
                .read_line(&mut input)
                .expect("Error reading input");
            if LUA_STATE != 0 {
                loadbuffer(LUA_STATE, input.as_ptr(), input.len(), input.as_ptr());
                if pcall(LUA_STATE, 0, 0, 0) != 0 {
                    println!("{:?}", tolstring(LUA_STATE, -1));
                } else {
                    println!("Executed!")
                }
                // New thread does not work
                LUA_STATE = new_thread(LUA_STATE);
            }
        }
    }
}

#[no_mangle]
pub extern "stdcall" fn DllMain(
    _hinst_dll: winapi::shared::minwindef::HINSTANCE,
    fdw_reason: u32,
    _: *mut winapi::ctypes::c_void,
) {
    if fdw_reason == 1 {
        thread::spawn(entry_point);
    }
}

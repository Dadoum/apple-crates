use adi::core_adi::{CoreADIADIProxy, CoreADIParameters, CoreADIProxy};
use dlopen2::symbor::{Library, Symbol};

type CoreADIDispatcherFn = extern "C" fn(u32, *const CoreADIParameters) -> i32;

pub struct LibraryCoreADIProxy<'lt>(Symbol<'lt, CoreADIDispatcherFn>);

impl<'lt> LibraryCoreADIProxy<'lt> {
    pub fn new(library: &'lt Library) -> Result<Self, dlopen2::Error> {
        unsafe { library.symbol("vdfut768ig").map(LibraryCoreADIProxy) }
    }
}

impl Drop for LibraryCoreADIProxy<'_> {
    fn drop(&mut self) {
        let _ = self.finalize();
    }
}

impl CoreADIProxy for LibraryCoreADIProxy<'_> {
    unsafe fn dispatch(&self, function_code: u32, parameters: *const CoreADIParameters) -> i32 {
        self.0(function_code, parameters)
    }
}

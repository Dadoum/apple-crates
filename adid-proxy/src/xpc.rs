#![allow(unused)]

use block::RcBlock;
use std::cmp::PartialEq;
use std::ffi::CStr;
use std::mem::MaybeUninit;
use std::ops::Deref;
use std::ptr::null_mut;
use std::{mem, slice};
use xpc_connection_sys::{
    _xpc_dictionary_s, _xpc_type_s, dispatch_queue_t, xpc_connection_create_mach_service,
    xpc_connection_resume, xpc_connection_send_message_with_reply_sync,
    xpc_connection_set_event_handler, xpc_connection_t, xpc_data_create,
    xpc_dictionary_create_empty, xpc_dictionary_get_data, xpc_dictionary_get_value,
    xpc_dictionary_set_value, xpc_get_type, xpc_object_t, xpc_release, xpc_type_t,
};

pub struct XpcConnection(xpc_connection_t);

impl XpcConnection {
    pub fn create_mach_service(name: &CStr, targetq: Option<dispatch_queue_t>, flags: u64) -> Self {
        unsafe {
            XpcConnection(xpc_connection_create_mach_service(
                name.as_ptr(),
                targetq.unwrap_or(null_mut()),
                flags,
            ))
        }
    }

    pub fn set_event_handler(&self, block: RcBlock<(XpcObject,), ()>) {
        unsafe {
            xpc_connection_set_event_handler(self.0, block.deref() as *const _ as *mut _);
        }
    }

    pub fn resume(&self) {
        unsafe { xpc_connection_resume(self.0) }
    }

    pub fn send_message_with_reply_sync(
        &self,
        message: &XpcDictionary,
    ) -> Result<XpcDictionary, XpcError> {
        unsafe {
            let ret = XpcObject(xpc_connection_send_message_with_reply_sync(
                self.0,
                message.0.0,
            ));
            let typ = ret.get_type();
            if typ == XPC_TYPE_ERROR {
                return Err(XpcError(ret));
            }
            assert_eq!(typ, XPC_TYPE_DICTIONARY);
            Ok(XpcDictionary(ret))
        }
    }
}

impl Drop for XpcConnection {
    fn drop(&mut self) {
        unsafe { xpc_release(self.0 as xpc_object_t) }
    }
}

#[derive(Debug, PartialEq)]
pub struct XpcType(xpc_type_t);

const XPC_TYPE_DICTIONARY: XpcType =
    XpcType(unsafe { (&xpc_connection_sys::_xpc_type_dictionary) as *const _xpc_type_s });

const XPC_TYPE_ERROR: XpcType =
    XpcType(unsafe { (&xpc_connection_sys::_xpc_type_error) as *const _xpc_type_s });

pub struct XpcError(pub XpcObject);

const XPC_ERROR_CONNECTION_INTERRUPTED: XpcError = XpcError(XpcObject(
    (unsafe {
        (&xpc_connection_sys::_xpc_error_connection_interrupted) as *const _xpc_dictionary_s
    }) as xpc_object_t,
));

const XPC_ERROR_CONNECTION_INVALID: XpcError = XpcError(XpcObject(
    (unsafe { (&xpc_connection_sys::_xpc_error_connection_invalid) as *const _xpc_dictionary_s })
        as xpc_object_t,
));

pub struct XpcObject(xpc_object_t);

impl XpcObject {
    pub fn get_type(&self) -> XpcType {
        XpcType(unsafe { xpc_get_type(self.0) })
    }
}

impl Drop for XpcObject {
    fn drop(&mut self) {
        unsafe { xpc_release(self.0) }
    }
}

pub struct XpcData(pub XpcObject);

impl XpcData {
    pub fn create(bytes: &[u8]) -> Self {
        unsafe {
            XpcData(XpcObject(xpc_data_create(
                bytes.as_ptr() as _,
                bytes.len() as _,
            )))
        }
    }
}

pub struct XpcDictionary(pub XpcObject);

impl XpcDictionary {
    pub fn create_empty() -> Self {
        unsafe { XpcDictionary(XpcObject(xpc_dictionary_create_empty())) }
    }

    pub fn set_value(&self, key: &CStr, value: XpcObject) {
        unsafe {
            let object = value.0;
            mem::forget(value);
            xpc_dictionary_set_value(self.0.0, key.as_ptr(), object);
        }
    }

    pub fn get_value(&self, key: &CStr) -> XpcObject {
        unsafe { XpcObject(xpc_dictionary_get_value(self.0.0, key.as_ptr())) }
    }

    pub fn get_data(&self, key: &CStr) -> &[u8] {
        unsafe {
            let mut length = MaybeUninit::uninit();
            let data =
                xpc_dictionary_get_data(self.0.0, key.as_ptr(), length.as_mut_ptr()) as *const u8;

            slice::from_raw_parts(data, length.assume_init() as _)
        }
    }
}

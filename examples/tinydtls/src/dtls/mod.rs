extern crate libc;
extern {
	fn rust_dtls_init();
}

// A public function
pub unsafe fn dtls_init() {
	rust_dtls_init();
}
/*
    // A private function
    fn private_function() {
        println!("called `my::private_function()`");
    }

    // Items can access other items in the same module
    pub fn indirect_access() {
        print!("called `my::indirect_access()`, that\n> ");

        // regardless of their visibility
        private_function();
    }

    // A public module
    pub mod nested {
        pub fn function() {
            println!("called `my::nested::function()`");
        }

        #[allow(dead_code)]
        fn private_function() {
            println!("called `my::nested::private_function()`");
        }
    }

    // A private module
    mod inaccessible {
        #[allow(dead_code)]
        pub fn public_function() {
            println!("called `my::inaccessible::public_function()`");
        }
    }*/

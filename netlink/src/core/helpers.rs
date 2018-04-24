
/// Creates an enum with various traits. 
/// The first key-value pair is the default used if any conversion would fail.
#[macro_export]
macro_rules! extended_enum_default {
    ( $name:ident, $ty:ty, $var_def:ident => $val_def:expr,
      $( $var:ident => $val:expr ),+ $(,)* ) => (
        
        #[derive(Clone,Debug,Eq,PartialEq)]
        pub enum $name {
            $var_def,
            $($var,)*
        }

        impl From<$ty> for $name {
            fn from(v: $ty) -> Self {
                match v {
                    $val_def => $name::$var_def,
                    $( $val => $name::$var,)*
                    _ => $name::$var_def,
                }
            }
        }

        impl From<$name> for $ty {
            fn from(v: $name) -> Self {
                match v {
                    $name::$var_def => $val_def,
                    $( $name::$var => $val, )*
                }
            }
        }

        impl ConvertFrom<$ty> for $name {
            fn convert_from(v: $ty) -> Option<Self> {
                match v {
                    $val_def => Some($name::$var_def),
                    $( $val => Some($name::$var),)*
                    _ => None,
                }
            }
        }

        impl PartialEq<$name> for $ty {
            fn eq(&self, other: &$name) -> bool {
                match *other {
                    $name::$var_def => *self == $val_def,
                    $( $name::$var => *self == $val, )*
                }
            }

            fn ne(&self, other: &$name) -> bool {
                match *other {
                    $name::$var_def => *self != $val_def,
                    $( $name::$var => *self != $val, )*
                }
            }
        }
    );
}

/// Creates an enum with various traits. 
/// The first key-value pair is the default used if any conversion would fail.
#[macro_export]
macro_rules! extended_enum {
    ( $name:ident, $ty:ty, $( $var:ident => $val:expr ),+ $(,)* ) => (
        
        #[derive(Clone,Debug,Eq,PartialEq)]
        pub enum $name {
            $($var,)*
        }

        impl From<$ty> for $name {
            fn from(v: $ty) -> Self {
                match v {
                    $( $val => $name::$var,)*
                    _ => panic!("Bad Value"),
                }
            }
        }

        impl From<$name> for $ty {
            fn from(v: $name) -> Self {
                match v {
                    $( $name::$var => $val, )*
                }
            }
        }

        impl ConvertFrom<$ty> for $name {
            fn convert_from(v: $ty) -> Option<Self> {
                match v {
                    $( $val => Some($name::$var),)*
                    _ => None,
                }
            }
        }

        impl PartialEq<$name> for $ty {
            fn eq(&self, other: &$name) -> bool {
                match *other {
                    $( $name::$var => *self == $val, )*
                }
            }

            fn ne(&self, other: &$name) -> bool {
                match *other {
                    $( $name::$var => *self != $val, )*
                }
            }
        }
    );
}
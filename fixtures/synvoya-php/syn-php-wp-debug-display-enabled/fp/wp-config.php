<?php
define( 'DB_NAME', 'wordpress' );
define( 'WP_DEBUG', true );
define( 'WP_DEBUG_LOG', true );
define( 'WP_DEBUG_DISPLAY', false );
if ( getenv( 'WP_ENV' ) === 'development' ) {
    define( 'SCRIPT_DEBUG', true );
}

<?php
class RowsQueryScope {
    public function __construct() {
        $this->token = uniqid( 'cortext_rows_', true );
    }
}

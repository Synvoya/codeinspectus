<?php
class InvoiceController {
    public function upload(Request $request) {
        $uploadedFile = $request->files->get('document');
        $originalName = $uploadedFile->getClientOriginalName();
        $extension = null;
        foreach (self::ALLOWED_EXTENSIONS as $ext) {
            if (substr_compare($originalName, $ext, -strlen($ext)) === 0) {
                $extension = $ext;
            }
        }
        $uploadedFile->move($this->dir, substr($originalName, 0, 20) . $extension);
    }
}

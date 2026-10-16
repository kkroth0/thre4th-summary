import fs from 'node:fs';

// Atomic recovery copy with bounded serialization memory. Never serialize the
// entire historical archive into one extra (potentially very large) string.
export function writeNewsBackupAtomic(file, rows, io = fs) {
    if (!Array.isArray(rows)) throw Error('Invalid news backup');
    const temporary = `${file}.${process.pid}.tmp`;
    let fd; let parts = ['[']; let length = 1;
    const flush = () => {
        const buffer = Buffer.from(parts.join('')); let offset = 0;
        while (offset < buffer.length) {
            const written = io.writeSync(fd, buffer, offset, buffer.length - offset);
            if (!written) throw Error('Incomplete news backup write');
            offset += written;
        }
        parts = []; length = 0;
    };
    try {
        fd = io.openSync(temporary, 'w', 0o600);
        for (let index = 0; index < rows.length; index++) {
            const text = (index ? ',\n' : '\n') + (JSON.stringify(rows[index]) ?? 'null');
            parts.push(text); length += Buffer.byteLength(text);
            if (length >= 256 * 1024) flush();
        }
        parts.push('\n]\n'); flush(); io.fsyncSync(fd); io.closeSync(fd); fd = undefined;
        io.renameSync(temporary, file);
    } catch (error) {
        if (fd !== undefined) try { io.closeSync(fd); } catch { /* preserve original error */ }
        try { io.unlinkSync(temporary); } catch { /* retain old recovery file */ }
        throw error;
    }
}

/** Date inputs represent whole days in the browser's local timezone. */
export function newsExportRange(from: string, to: string) {
  const date = (value: string, end: boolean) => {
    if (!/^\d{4}-\d{2}-\d{2}$/.test(value)) throw new Error('Invalid date');
    const [year, month, day] = value.split('-').map(Number);
    const result = new Date(year, month - 1, day);
    if (result.getFullYear() !== year || result.getMonth() !== month - 1 || result.getDate() !== day) throw new Error('Invalid date');
    if (end) result.setHours(23, 59, 59, 999);
    return result.toISOString();
  };
  if (from > to) throw new Error('Invalid range');
  return { from: date(from, false), to: date(to, true) };
}

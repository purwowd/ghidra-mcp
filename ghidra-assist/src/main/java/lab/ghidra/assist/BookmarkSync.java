package lab.ghidra.assist;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Bookmark;
import ghidra.program.model.listing.BookmarkManager;
import ghidra.program.model.listing.BookmarkType;
import ghidra.program.model.listing.Program;

/**
 * Bidirectional sync between findings markdown addresses and Ghidra NOTE bookmarks.
 */
public final class BookmarkSync {

    public static final String CATEGORY = "GhidraAssist";
    private static final Pattern ADDR = Pattern.compile("0x[0-9a-fA-F]{4,}");

    private BookmarkSync() {
    }

    public static final class SyncResult {
        public final int fromFindings;
        public final int fromBookmarks;
        public final String detail;

        public SyncResult(int fromFindings, int fromBookmarks, String detail) {
            this.fromFindings = fromFindings;
            this.fromBookmarks = fromBookmarks;
            this.detail = detail;
        }
    }

    /**
     * Create bookmarks for addresses found in findings text; append bookmark list into findings return string.
     */
    public static SyncResult sync(Program program, String findingsMarkdown) {
        if (program == null) {
            return new SyncResult(0, 0, "No program");
        }
        int created = 0;
        Set<String> seen = new HashSet<>();
        if (findingsMarkdown != null) {
            Matcher m = ADDR.matcher(findingsMarkdown);
            int tx = program.startTransaction("GhidraAssist bookmark sync");
            boolean ok = false;
            try {
                BookmarkManager bm = program.getBookmarkManager();
                while (m.find()) {
                    String tok = m.group();
                    if (!seen.add(tok)) {
                        continue;
                    }
                    Address addr = program.getAddressFactory().getAddress(tok);
                    if (addr == null) {
                        continue;
                    }
                    Bookmark existing = bm.getBookmark(addr, BookmarkType.NOTE, CATEGORY);
                    if (existing != null) {
                        continue;
                    }
                    bm.setBookmark(addr, BookmarkType.NOTE, CATEGORY, "from findings");
                    created++;
                    if (created >= 50) {
                        break;
                    }
                }
                ok = true;
            }
            finally {
                program.endTransaction(tx, ok);
            }
        }

        List<String> lines = new ArrayList<>();
        BookmarkManager bm = program.getBookmarkManager();
        Iterator<Bookmark> it = bm.getBookmarksIterator(BookmarkType.NOTE);
        int listed = 0;
        while (it.hasNext()) {
            Bookmark b = it.next();
            if (!CATEGORY.equals(b.getCategory())) {
                continue;
            }
            lines.add("- " + b.getAddress() + " — " + (b.getComment() == null ? "" : b.getComment()));
            listed++;
            if (listed >= 100) {
                break;
            }
        }
        String export = lines.isEmpty()
            ? ""
            : "\n\n## Bookmarks (" + CATEGORY + ")\n" + String.join("\n", lines) + "\n";
        return new SyncResult(created, listed,
            "bookmarks created=" + created + ", listed=" + listed + export);
    }
}

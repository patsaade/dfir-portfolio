// Shared pixel-star geometry. Pure + deterministic, so the favicon, social-card
// lockup, and the on-page <PixelStar> component all rasterize the identical star.
// No DOM, no fonts, no I/O — safe to import from build scripts and Astro frontmatter.

export const STAR_GRID = 13; // raster resolution (chunky, legible down to ~16px)

// Inner-radius ratio (point sharpness). 0.5 reads as a clean 5-point silhouette
// at 13px while staying chunky enough that the arms don't thin to single pixels.
const INNER_RATIO = 0.5;

// Optical centring nudge, in cells. The star's OUTLINE is centred exactly by the
// bounding-box math below, but its INK isn't: the two bottom legs taper to points,
// so the lowest row is sparse enough to sample empty while the top spike still
// registers. A quarter-cell downward shift rebalances the rendered ink (equal
// blank rows above and below) without breaking the outline's symmetry.
const OPTICAL_DY = 0.25;

// (col,row) cells of a grid×grid raster whose centers fall inside a point-up
// 5-point star. Deterministic, so the icon is byte-identical everywhere.
//
// The star is normalized by its OWN BOUNDING BOX, not by the circumscribed
// circle it's generated from. That distinction is the whole point: a point-up
// star's top vertex reaches -R while its two bottom vertices only reach
// sin(54°)·R ≈ 0.809R, so the polygon's box is NOT centred on the circle's
// centre. Placing it by the circle (the previous approach) left the mark sitting
// high and left in its own viewBox — measured at grid 13: 1 blank row above vs 3
// below, 1 blank column left vs 2 right, and 10 cells with no mirror partner.
export function starCells(grid = STAR_GRID) {
  // Unit star centred on the origin.
  const pts = [];
  for (let i = 0; i < 10; i++) {
    const a = -Math.PI / 2 + (i * Math.PI) / 5;
    const rad = i % 2 === 0 ? 1 : INNER_RATIO;
    pts.push([rad * Math.cos(a), rad * Math.sin(a)]);
  }

  // Fit that box to the grid and centre it on both axes.
  const xs = pts.map((p) => p[0]);
  const ys = pts.map((p) => p[1]);
  const minX = Math.min(...xs);
  const minY = Math.min(...ys);
  const w = Math.max(...xs) - minX;
  const h = Math.max(...ys) - minY;
  const scale = grid / Math.max(w, h);
  const offX = (grid - w * scale) / 2 - minX * scale;
  const offY = (grid - h * scale) / 2 - minY * scale + OPTICAL_DY;
  const poly = pts.map(([x, y]) => [x * scale + offX, y * scale + offY]);

  // Sample at cell centres (x+0.5), which are symmetric about grid/2 — the
  // previous code compared them against (grid-1)/2, a half-cell off, which is
  // where the left/right asymmetry came from independently of the box issue.
  const inside = (px, py) => {
    let hit = false;
    for (let i = 0, j = poly.length - 1; i < poly.length; j = i++) {
      const [xi, yi] = poly[i];
      const [xj, yj] = poly[j];
      if (yi > py !== yj > py && px < ((xj - xi) * (py - yi)) / (yj - yi) + xi) hit = !hit;
    }
    return hit;
  };

  const cells = [];
  for (let y = 0; y < grid; y++) {
    for (let x = 0; x < grid; x++) {
      if (inside(x + 0.5, y + 0.5)) cells.push([x, y]);
    }
  }
  return cells;
}

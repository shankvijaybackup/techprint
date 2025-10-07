# TechPrint – Live Web Technology Fingerprinting Tool

TechPrint performs real-time analysis of live websites to identify the technologies in use. The solution is split into a modern single-page React frontend and a lightweight Node.js backend that executes the scanning logic.

## Architecture

- `techprint.html` (Frontend): A single-file React application that provides the user interface. It accepts a target URL and calls the backend API for results.
- `server.js` (Backend): An Express server that fetches the requested URL, applies TechPrint’s signature database, and returns detected technologies as JSON.
- `package.json`: Defines backend dependencies (`express`, `cors`, `axios`) and the start script.

Separating the frontend and backend is required because browser sandboxing (CORS) blocks webpages from fetching and inspecting other domains directly.

## Prerequisites

- Node.js 18+ (includes `npm`)

## Step 1: Set Up the Backend

1. Install dependencies:
   ```bash
   npm install
   ```
2. Start the server (runs both the API and serves the UI):
   ```bash
   npm run dev
   ```
   The terminal should display:
   ```
   TechPrint backend server running on http://localhost:3001
   Open http://localhost:3001/ in your browser to use the TechPrint UI.
   ```
3. Leave this terminal session open while you use the application.

To run on a different port, set `PORT` before the command (e.g., `PORT=7000 npm run dev` on macOS/Linux or `set PORT=7000 && npm run dev` in PowerShell).

## Step 2: Launch the Frontend

1. With the backend still running, open `http://localhost:3001/` in a modern browser (Chrome, Edge, Firefox, etc.).
2. The bundled React UI is served by the Node.js process, so no additional static server is required.

## Step 3: Run a Scan

1. Ensure the backend server is still running at `http://localhost:3001`.
2. In the TechPrint UI, enter a full URL such as `https://www.netlify.com` or `https://vuejs.org`.
3. Click **Run Scan**. The frontend sends the request to the backend, which downloads and analyzes the target site, then returns a breakdown of detected technologies, confidence, versions, and (when available) risk guidance.
4. Use the **Switch Theme** button (top-right) to toggle between light and dark modes.
5. Use the **Download JSON** or **Download CSV** buttons beneath the results to export the scan data for further analysis or reporting.

## Additional Notes

- The backend enforces a 10-second timeout; very slow or unreachable sites will return an error.
- Each scan performs a deep inspection by following up to 10 linked JavaScript bundles (in addition to the base HTML and response headers), which surfaces client-side technologies such as chat widgets that load dynamically.
- CORS is enabled so the static frontend can call `http://localhost:3001` even when opened directly from the file system.
- Adjust `API_ENDPOINT` inside `techprint.html` if you host the backend on a different port or machine.

## Deploying to Vercel (Free Tier)

The repository includes a Vercel-ready setup:

1. Install the Vercel CLI if you don’t have it yet:
   ```bash
   npm install -g vercel
   ```
2. From the project root, run:
   ```bash
   vercel
   ```
   Follow the prompts to link to (or create) a Vercel project.
3. Deploy updates with:
   ```bash
   vercel --prod
   ```

Vercel serves `techprint.html` at the root URL and hosts the deep-scanning API at `/api/scan` via a serverless function (`api/scan.js`). No paid plan is required for basic usage.

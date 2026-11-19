import { Route, Routes } from "react-router-dom";
import { CaseShell } from "./components/AppShell";
import AttackPage from "./pages/Attack";
import CaseList from "./pages/CaseList";
import Collect from "./pages/Collect";
import DiffPage from "./pages/Diff";
import EvidencePage from "./pages/Evidence";
import FindingsPage from "./pages/Findings";
import GraphPage from "./pages/Graph";
import NetworkPage from "./pages/Network";
import ProcessesPage from "./pages/Processes";
import ReportPage from "./pages/Report";
import Story from "./pages/Story";
import SummaryPage from "./pages/Summary";
import TimelinePage from "./pages/Timeline";
import VerifyPage from "./pages/Verify";

export default function App() {
  return (
    <Routes>
      <Route path="/" element={<CaseList />} />
      <Route path="/verify/:id" element={<VerifyPage />} />
      <Route path="/cases/:id/*" element={
        <CaseShell>
          <Routes>
            <Route index element={<SummaryPage />} />
            <Route path="collect" element={<Collect />} />
            <Route path="story" element={<Story />} />
            <Route path="timeline" element={<TimelinePage />} />
            <Route path="graph" element={<GraphPage />} />
            <Route path="processes" element={<ProcessesPage />} />
            <Route path="network" element={<NetworkPage />} />
            <Route path="findings" element={<FindingsPage />} />
            <Route path="attack" element={<AttackPage />} />
            <Route path="diff" element={<DiffPage />} />
            <Route path="evidence" element={<EvidencePage />} />
            <Route path="report" element={<ReportPage />} />
          </Routes>
        </CaseShell>
      } />
      <Route path="*" element={<CaseList />} />
    </Routes>
  );
}

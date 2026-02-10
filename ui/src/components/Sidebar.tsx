import React from "react";
import { NavLink } from "react-router-dom";

const NAV_ITEMS = [
  { to: "/topology", label: "Topology", icon: "&#9678;" },
  { to: "/dashboard", label: "Dashboard", icon: "&#9632;" },
  { to: "/connections", label: "Connections", icon: "&#8644;" },
  { to: "/requests", label: "Requests", icon: "&#8680;" },
];

const styles: Record<string, React.CSSProperties> = {
  sidebar: {
    position: "fixed",
    top: 0,
    left: 0,
    width: "240px",
    height: "100vh",
    backgroundColor: "#161b22",
    borderRight: "1px solid #30363d",
    display: "flex",
    flexDirection: "column",
    padding: "0",
    zIndex: 100,
  },
  brand: {
    padding: "20px 24px",
    fontSize: "20px",
    fontWeight: 700,
    color: "#58a6ff",
    borderBottom: "1px solid #30363d",
    letterSpacing: "0.5px",
  },
  nav: {
    flex: 1,
    padding: "12px 0",
    display: "flex",
    flexDirection: "column",
    gap: "2px",
  },
  link: {
    display: "flex",
    alignItems: "center",
    gap: "12px",
    padding: "10px 24px",
    color: "#8b949e",
    textDecoration: "none",
    fontSize: "14px",
    fontWeight: 500,
    transition: "background-color 0.15s, color 0.15s",
    borderLeft: "3px solid transparent",
  },
  linkActive: {
    color: "#e6edf3",
    backgroundColor: "#1c2129",
    borderLeftColor: "#58a6ff",
  },
  linkIcon: {
    fontSize: "16px",
    width: "20px",
    textAlign: "center" as const,
  },
  footer: {
    padding: "16px 24px",
    borderTop: "1px solid #30363d",
    fontSize: "11px",
    color: "#484f58",
  },
};

const Sidebar: React.FC = () => {
  return (
    <aside style={styles.sidebar}>
      <div style={styles.brand}>nefi</div>
      <nav style={styles.nav}>
        {NAV_ITEMS.map((item) => (
          <NavLink
            key={item.to}
            to={item.to}
            style={({ isActive }) => ({
              ...styles.link,
              ...(isActive ? styles.linkActive : {}),
            })}
          >
            <span
              style={styles.linkIcon}
              dangerouslySetInnerHTML={{ __html: item.icon }}
            />
            {item.label}
          </NavLink>
        ))}
      </nav>
      <div style={styles.footer}>
        nefi v0.1.0
        <br />
        Kubernetes Mesh Observability
      </div>
    </aside>
  );
};

export default Sidebar;

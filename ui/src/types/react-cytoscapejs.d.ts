declare module "react-cytoscapejs" {
  import cytoscape from "cytoscape";
  import { Component } from "react";

  interface CytoscapeComponentProps {
    elements: cytoscape.ElementDefinition[];
    stylesheet?: cytoscape.StylesheetStyle[];
    layout?: cytoscape.LayoutOptions;
    style?: React.CSSProperties;
    cy?: (cy: cytoscape.Core) => void;
    className?: string;
    id?: string;
    zoom?: number;
    pan?: cytoscape.Position;
    minZoom?: number;
    maxZoom?: number;
    zoomingEnabled?: boolean;
    userZoomingEnabled?: boolean;
    panningEnabled?: boolean;
    userPanningEnabled?: boolean;
    boxSelectionEnabled?: boolean;
    autoungrabify?: boolean;
    autounselectify?: boolean;
  }

  export default class CytoscapeComponent extends Component<CytoscapeComponentProps> {}
}

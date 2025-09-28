import React from "react";

export default class ErrorBoundary extends React.Component {
  constructor(props){ super(props); this.state = { hasError:false, error:null }; }
  static getDerivedStateFromError(error){ return { hasError:true, error }; }
  componentDidCatch(error, info){ console.error("[E3] ErrorBoundary", error, info); }
  render(){
    if(this.state.hasError){
      return (
        <div style={{border:"2px solid #dc2626", background:"#fff1f2", color:"#991b1b", padding:12, borderRadius:8}}>
          <b>Erreur React capturée :</b>
          <pre style={{whiteSpace:"pre-wrap"}}>{String(this.state.error)}</pre>
        </div>
      );
    }
    return this.props.children;
  }
}

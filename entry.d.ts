export interface ICvss {
    score: number;
    vectorString: string;
}

export interface IVia {
    source: number;
    name: string;
    dependency: string;
    title: string;
    url: string;
    severity: string;
    cwe: string[];
    cvss: ICvss;
    range: string;
}

export interface IEntry {
    name: string;
    severity: string;
    isDirect: boolean;
    via?: IVia[]|string[];
    effects: string[];
    range: string;
    nodes: string[];
    fixAvailable: boolean|IFix;
}


export interface IFix {
    name: string;
    version: string,
    isSemVerMajor: boolean;
}

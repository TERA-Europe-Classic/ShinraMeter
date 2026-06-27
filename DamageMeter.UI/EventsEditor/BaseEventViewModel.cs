using Data.Actions;
using Data.Actions.Notify;
using Data.Events;
using System.Collections.Generic;
using System.Linq;
using System.Windows.Threading;
using Tera.Game;

namespace DamageMeter.UI
{
    public class BaseEventViewModel : TSPropertyChanged
    {
        protected readonly Event Event;
        private bool _active;
        private bool _ingame;
        private bool _isExpanded;
        private int _priority;
        private bool _outOfCombat;
        private string _searchText = string.Empty;

        public bool Active
        {
            get => _active;
            set
            {
                if (_active == value) return;
                _active = value;
                Event.Active = value;
                NotifyPropertyChanged();
                NotifyPropertyChanged(nameof(StatusText));
                RefreshSearchText();
            }
        }

        public bool InGame
        {
            get => _ingame;
            set
            {
                if (_ingame == value) return;
                _ingame = value;
                Event.InGame = value;
                NotifyPropertyChanged();
                NotifyPropertyChanged(nameof(StatusText));
                RefreshSearchText();
            }
        }

        public bool OutOfCombat
        {
            get => _outOfCombat;
            set
            {
                if (_outOfCombat == value) return;
                _outOfCombat = value;
                Event.OutOfCombat = value;
                NotifyPropertyChanged();
                NotifyPropertyChanged(nameof(StatusText));
                RefreshSearchText();
            }
        }

        public int Priority
        {
            get => _priority;
            set
            {
                if (_priority == value) return;
                _priority = value;
                Event.Priority = value;
                NotifyPropertyChanged();
                RefreshSearchText();
            }
        }

        public virtual string Type => "Event";
        public virtual string Summary => Type;
        public bool IsExpanded
        {
            get => _isExpanded;
            set
            {
                if (_isExpanded == value) return;
                _isExpanded = value;
                NotifyPropertyChanged();
            }
        }

        public string StatusText => $"{(Active ? "Enabled" : "Off")} / {(InGame ? "In game" : "Out of game")}{(OutOfCombat ? " / OOC" : "")}";
        public string DeliverySummary => Actions.Count == 0 ? "No actions" : string.Join(", ", Actions.Select(a => a.DeliverySummary));
        public string SearchText => _searchText;

        public SynchronizedObservableCollection<BlackListItemVM> BlacklistedBosses { get; }
        public SynchronizedObservableCollection<PlayerClass> BlacklistedClasses { get; }
        public SynchronizedObservableCollection<ActionVM> Actions { get; }

        public BaseEventViewModel(Event ev, List<Action> act) : base(Dispatcher.CurrentDispatcher)
        {
            Event = ev;
            var dispatcher = Dispatcher.CurrentDispatcher;
            BlacklistedBosses = new SynchronizedObservableCollection<BlackListItemVM>(dispatcher);
            BlacklistedClasses = new SynchronizedObservableCollection<PlayerClass>(dispatcher);
            Actions = new SynchronizedObservableCollection<ActionVM>(dispatcher);
            _active = ev.Active;
            _ingame = ev.InGame;
            _priority = ev.Priority;
            _outOfCombat = ev.OutOfCombat;
            ev.AreaBossBlackList.ForEach(b => BlacklistedBosses.Add(new BlackListItemVM(b.AreaId, b.BossId)));
            ev.IgnoreClasses.ForEach(BlacklistedClasses.Add);

            act.ForEach(action =>
            {
                if (action is not NotifyAction na) return;
                var actionVm = new ActionVM(na);
                actionVm.PropertyChanged += (_, args) =>
                {
                    if (args.PropertyName == nameof(ActionVM.SearchText) || args.PropertyName == nameof(ActionVM.DeliverySummary))
                    {
                        NotifyPropertyChanged(nameof(DeliverySummary));
                        RefreshSearchText();
                    }
                };
                Actions.Add(actionVm);
            });
        }

        protected virtual string BuildSearchText()
        {
            return $"{Type} {Summary} {(Active ? "active enabled on" : "inactive disabled off")} {(InGame ? "ingame in game" : "outgame out of game")} {(OutOfCombat ? "out of combat ooc" : "")} priority {Priority} {DeliverySummary} {string.Join(" ", Actions.Select(a => a.SearchText))}";
        }

        protected void RefreshSearchText()
        {
            _searchText = BuildSearchText();
            NotifyPropertyChanged(nameof(SearchText));
        }
    }
}
